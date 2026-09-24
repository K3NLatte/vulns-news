package npm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"vulns-news/src/domain"
)

const ecosystemName = "npm"

var (
	// ErrFileTooLarge indicates that a manifest or lockfile exceeded MaxFileSize.
	ErrFileTooLarge = errors.New("npm profile file exceeds size limit")
	// ErrTooManyFiles indicates that repository traversal exceeded MaxFiles.
	ErrTooManyFiles = errors.New("npm profile repository exceeds file limit")
	// ErrMaxDepth indicates that repository traversal exceeded MaxDepth.
	ErrMaxDepth = errors.New("npm profile repository exceeds depth limit")
	// ErrUnsupportedLockfile indicates a package-lock.json version other than 2 or 3.
	ErrUnsupportedLockfile = errors.New("unsupported npm lockfile version")
)

// Limits bounds work performed on untrusted repository contents.
type Limits struct {
	MaxFileSize int64
	MaxFiles    int
	MaxDepth    int
}

// DefaultLimits returns conservative limits suitable for repository profiling.
func DefaultLimits() Limits {
	return Limits{
		MaxFileSize: 10 << 20,
		MaxFiles:    100_000,
		MaxDepth:    64,
	}
}

// ProfileFragment is the npm-owned portion of a domain.RepositoryProfile.
type ProfileFragment struct {
	Ecosystems []domain.EcosystemUsage `json:"ecosystems"`
	Components []domain.Component      `json:"components"`
}

// Profiler parses npm metadata with explicit resource limits.
type Profiler struct {
	limits Limits
}

// New returns a profiler configured with DefaultLimits.
func New() *Profiler {
	return &Profiler{limits: DefaultLimits()}
}

// NewProfiler returns a profiler configured with limits. Every limit must be
// positive so a zero value cannot accidentally disable a safety boundary.
func NewProfiler(limits Limits) (*Profiler, error) {
	if limits.MaxFileSize <= 0 || limits.MaxFiles <= 0 || limits.MaxDepth <= 0 {
		return nil, errors.New("npm profiler limits must be positive")
	}
	return &Profiler{limits: limits}, nil
}

// Profile profiles the directory rooted at root. It never invokes npm or any
// executable in the repository.
func Profile(root string) (ProfileFragment, error) {
	return New().Profile(root)
}

// ProfileFS profiles an fs.FS with DefaultLimits.
func ProfileFS(fsys fs.FS) (ProfileFragment, error) {
	return New().ProfileFS(fsys)
}

// Profile profiles the directory rooted at root.
func (p *Profiler) Profile(root string) (ProfileFragment, error) {
	if strings.TrimSpace(root) == "" {
		return ProfileFragment{}, errors.New("npm profile root is empty")
	}
	return p.ProfileFS(os.DirFS(root))
}

// ProfileFS profiles manifests and lockfiles in fsys. node_modules, .git, and
// common pnpm/Yarn dependency stores are not traversed.
func (p *Profiler) ProfileFS(fsys fs.FS) (ProfileFragment, error) {
	if p == nil {
		return ProfileFragment{}, errors.New("npm profiler is nil")
	}
	if fsys == nil {
		return ProfileFragment{}, errors.New("npm profile filesystem is nil")
	}

	files, err := p.discover(fsys)
	if err != nil {
		return ProfileFragment{}, err
	}

	manifests := make(map[string]manifest)
	manifestPaths := make([]string, 0)
	lockPaths := make([]string, 0)
	for _, file := range files {
		contents, readErr := p.readBounded(fsys, file)
		if readErr != nil {
			return ProfileFragment{}, fileError(file, readErr)
		}
		switch path.Base(file) {
		case "package.json":
			parsed, parseErr := parseManifest(contents)
			if parseErr != nil {
				return ProfileFragment{}, fileError(file, parseErr)
			}
			manifests[path.Dir(file)] = parsed
			manifestPaths = append(manifestPaths, file)
		case "package-lock.json":
			lockPaths = append(lockPaths, file)
		}
	}

	locks := make(map[string]lockfile, len(lockPaths))
	lockDirectories := make(map[string]bool, len(lockPaths))
	for _, lockPath := range lockPaths {
		contents, readErr := p.readBounded(fsys, lockPath)
		if readErr != nil {
			return ProfileFragment{}, fileError(lockPath, readErr)
		}
		parsed, parseErr := parseLockfile(contents)
		if parseErr != nil {
			return ProfileFragment{}, fileError(lockPath, parseErr)
		}
		locks[lockPath] = parsed
		lockDirectories[path.Dir(lockPath)] = true
	}

	components := make([]domain.Component, 0)
	lockedNames := make(map[string]map[string]bool, len(lockPaths))
	for _, lockPath := range lockPaths {
		lockDirectory := path.Dir(lockPath)
		declarations := locks[lockPath].declarations()
		for manifestDirectory, manifest := range manifests {
			if nearestLockDirectory(manifestDirectory, lockDirectories) == lockDirectory {
				mergeDeclarations(declarations, manifest.declarations())
			}
		}
		lockedNames[lockDirectory] = make(map[string]bool)
		for _, candidate := range locks[lockPath].components(lockPath, declarations) {
			components = append(components, candidate)
			lockedNames[lockDirectory][candidate.Name] = true
		}
	}

	for directory, manifest := range manifests {
		lockDirectory := nearestLockDirectory(directory, lockDirectories)
		for name, declared := range manifest.declarations() {
			if lockedNames[lockDirectory][name] {
				continue
			}
			version := exactVersion(declared.spec)
			components = append(components, newComponent(path.Join(directory, "package.json"), name, version, true, declared.scope))
		}
	}

	components = normalizeComponents(components)
	fragment := ProfileFragment{Components: components}
	if len(manifestPaths) > 0 || len(lockPaths) > 0 {
		sort.Strings(manifestPaths)
		sort.Strings(lockPaths)
		fragment.Ecosystems = []domain.EcosystemUsage{{
			Name:      ecosystemName,
			Manifests: manifestPaths,
			Lockfiles: lockPaths,
		}}
	}
	return fragment, nil
}

func (p *Profiler) discover(fsys fs.FS) ([]string, error) {
	var files []string
	seen := 0
	err := fs.WalkDir(fsys, ".", func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fileError(filePath, walkErr)
		}
		if filePath != "." && pathDepth(filePath) > p.limits.MaxDepth {
			return fileError(filePath, ErrMaxDepth)
		}
		if filePath != "." {
			seen++
			if seen > p.limits.MaxFiles {
				return ErrTooManyFiles
			}
		}
		if entry.IsDir() {
			if filePath != "." && skippedDirectory(entry.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if entry.Type().IsRegular() && (entry.Name() == "package.json" || entry.Name() == "package-lock.json") {
			files = append(files, filePath)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func (p *Profiler) readBounded(fsys fs.FS, filePath string) ([]byte, error) {
	file, err := fsys.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	contents, err := io.ReadAll(io.LimitReader(file, p.limits.MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > p.limits.MaxFileSize {
		return nil, ErrFileTooLarge
	}
	return contents, nil
}

func nearestLockDirectory(directory string, lockDirectories map[string]bool) string {
	for {
		if lockDirectories[directory] {
			return directory
		}
		if directory == "." {
			return ""
		}
		directory = path.Dir(directory)
	}
}

func pathDepth(filePath string) int {
	if filePath == "." || filePath == "" {
		return 0
	}
	return strings.Count(filePath, "/") + 1
}

func skippedDirectory(name string) bool {
	switch name {
	case ".git", "node_modules", ".pnpm", ".yarn":
		return true
	default:
		return false
	}
}

func fileError(filePath string, err error) error {
	return fmt.Errorf("npm profile %s: %w", filePath, err)
}

type manifest struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type dependencyScope struct {
	scope string
	spec  string
}

func parseManifest(contents []byte) (manifest, error) {
	var parsed *manifest
	if err := decodeJSON(contents, &parsed); err != nil {
		return manifest{}, fmt.Errorf("parse package.json: %w", err)
	}
	if parsed == nil {
		return manifest{}, errors.New("parse package.json: expected a JSON object")
	}
	return *parsed, nil
}

func (m manifest) declarations() map[string]dependencyScope {
	result := make(map[string]dependencyScope)
	addDependencyMap(result, m.DevDependencies, "dev")
	addDependencyMap(result, m.Dependencies, "runtime")
	addDependencyMap(result, m.OptionalDependencies, "runtime")
	addDependencyMap(result, m.PeerDependencies, "runtime")
	return result
}

func addDependencyMap(destination map[string]dependencyScope, dependencies map[string]string, scope string) {
	for name, spec := range dependencies {
		if !validPackageName(name) {
			continue
		}
		existing, found := destination[name]
		if found && existing.scope == "runtime" {
			continue
		}
		destination[name] = dependencyScope{scope: scope, spec: spec}
	}
}

func mergeDeclarations(destination, source map[string]dependencyScope) {
	for name, declaration := range source {
		existing, found := destination[name]
		if !found || (existing.scope == "dev" && declaration.scope == "runtime") {
			destination[name] = declaration
		}
	}
}

type lockfile struct {
	LockfileVersion int                       `json:"lockfileVersion"`
	Packages        map[string]lockPackage    `json:"packages"`
	Dependencies    map[string]lockDependency `json:"dependencies"`
}

type lockPackage struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dev                  bool              `json:"dev"`
	DevOptional          bool              `json:"devOptional"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type lockDependency struct {
	Version      string                    `json:"version"`
	Dev          bool                      `json:"dev"`
	DevOptional  bool                      `json:"devOptional"`
	Dependencies map[string]lockDependency `json:"dependencies"`
}

func parseLockfile(contents []byte) (lockfile, error) {
	var parsed lockfile
	if err := decodeJSON(contents, &parsed); err != nil {
		return lockfile{}, fmt.Errorf("parse package-lock.json: %w", err)
	}
	if parsed.LockfileVersion != 2 && parsed.LockfileVersion != 3 {
		return lockfile{}, fmt.Errorf("%w: %d", ErrUnsupportedLockfile, parsed.LockfileVersion)
	}
	return parsed, nil
}

func decodeJSON(contents []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func (l lockfile) declarations() map[string]dependencyScope {
	result := make(map[string]dependencyScope)
	for packagePath, pkg := range l.Packages {
		if packagePath == "" || !strings.Contains(packagePath, "node_modules/") {
			mergeDeclarations(result, packageDeclarations(pkg))
		}
	}
	return result
}

func packageDeclarations(pkg lockPackage) map[string]dependencyScope {
	return manifest{
		Dependencies:         pkg.Dependencies,
		DevDependencies:      pkg.DevDependencies,
		OptionalDependencies: pkg.OptionalDependencies,
		PeerDependencies:     pkg.PeerDependencies,
	}.declarations()
}

func (l lockfile) components(sourcePath string, declarations map[string]dependencyScope) []domain.Component {
	components := make([]domain.Component, 0)
	if len(l.Packages) > 0 {
		packagePaths := make([]string, 0, len(l.Packages))
		for packagePath := range l.Packages {
			packagePaths = append(packagePaths, packagePath)
		}
		sort.Strings(packagePaths)
		for _, packagePath := range packagePaths {
			pkg := l.Packages[packagePath]
			if pkg.Link {
				continue
			}
			installedName := packageNameFromPath(packagePath)
			name := pkg.Name
			if name == "" {
				name = installedName
			}
			if !validPackageName(name) || packagePath == "" || !strings.Contains(packagePath, "node_modules/") {
				continue
			}
			declaration, direct := declarations[name]
			if !direct && installedName != name {
				declaration, direct = declarations[installedName]
			}
			direct = direct && strings.Count(packagePath, "node_modules/") == 1
			scope := "runtime"
			if pkg.Dev || pkg.DevOptional {
				scope = "dev"
			}
			if direct {
				scope = declaration.scope
			}
			components = append(components, newComponent(sourcePath, name, pkg.Version, direct, scope))
		}
		return components
	}

	var visit func(map[string]lockDependency, bool)
	visit = func(dependencies map[string]lockDependency, topLevel bool) {
		names := make([]string, 0, len(dependencies))
		for name := range dependencies {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			pkg := dependencies[name]
			if !validPackageName(name) {
				continue
			}
			declaration, declared := declarations[name]
			direct := declared && topLevel
			scope := "runtime"
			if pkg.Dev || pkg.DevOptional {
				scope = "dev"
			}
			if direct {
				scope = declaration.scope
			}
			components = append(components, newComponent(sourcePath, name, pkg.Version, direct, scope))
			visit(pkg.Dependencies, false)
		}
	}
	visit(l.Dependencies, true)
	return components
}

func packageNameFromPath(packagePath string) string {
	const marker = "node_modules/"
	index := strings.LastIndex(packagePath, marker)
	if index < 0 {
		return ""
	}
	return strings.TrimSuffix(packagePath[index+len(marker):], "/")
}

func validPackageName(name string) bool {
	if name == "" || strings.ContainsAny(name, "\\\x00") {
		return false
	}
	if strings.HasPrefix(name, "@") {
		parts := strings.Split(name, "/")
		return len(parts) == 2 && len(parts[0]) > 1 && parts[1] != ""
	}
	return !strings.Contains(name, "/")
}

func exactVersion(spec string) string {
	spec = strings.TrimSpace(spec)
	if strings.HasPrefix(spec, "=") {
		spec = strings.TrimSpace(strings.TrimPrefix(spec, "="))
	}
	if strings.HasPrefix(spec, "v") {
		spec = strings.TrimPrefix(spec, "v")
	}
	if spec == "" || strings.ContainsAny(spec, " <>~^*|,/\\") {
		return ""
	}

	core := spec
	if index := strings.IndexAny(core, "-+"); index >= 0 {
		if !validVersionSuffix(core[index:]) {
			return ""
		}
		core = core[:index]
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return ""
	}
	for _, part := range parts {
		if part == "" {
			return ""
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return ""
			}
		}
	}
	return spec
}

func validVersionSuffix(suffix string) bool {
	if len(suffix) < 2 {
		return false
	}
	for _, character := range suffix[1:] {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '-' || character == '+' {
			continue
		}
		return false
	}
	return true
}

func newComponent(sourcePath, name, version string, direct bool, scope string) domain.Component {
	namespace := ""
	if strings.HasPrefix(name, "@") {
		namespace = strings.SplitN(name, "/", 2)[0]
	}
	component := domain.Component{
		PURL:       packagePURL(name),
		Ecosystem:  ecosystemName,
		Namespace:  namespace,
		Name:       name,
		Version:    version,
		Direct:     direct,
		Scope:      scope,
		SourcePath: sourcePath,
	}
	component.ID = componentID(component)
	return component
}

func packagePURL(name string) string {
	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name, "/", 2)
		return "pkg:npm/" + percentEncode(parts[0]) + "/" + percentEncode(parts[1])
	}
	return "pkg:npm/" + percentEncode(name)
}

func percentEncode(value string) string {
	const hexadecimal = "0123456789ABCDEF"
	var encoded strings.Builder
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("-._~", rune(character)) {
			encoded.WriteByte(character)
			continue
		}
		encoded.WriteByte('%')
		encoded.WriteByte(hexadecimal[character>>4])
		encoded.WriteByte(hexadecimal[character&15])
	}
	return encoded.String()
}

func componentID(component domain.Component) string {
	identity := strings.Join([]string{
		component.Ecosystem,
		component.SourcePath,
		component.Name,
		component.Version,
	}, "\x00")
	digest := sha256.Sum256([]byte(identity))
	return "npm-" + hex.EncodeToString(digest[:])
}

func normalizeComponents(components []domain.Component) []domain.Component {
	byIdentity := make(map[string]domain.Component)
	for _, component := range components {
		key := strings.Join([]string{component.SourcePath, component.Name, component.Version}, "\x00")
		existing, found := byIdentity[key]
		if !found {
			byIdentity[key] = component
			continue
		}
		if component.Direct {
			existing.Direct = true
		}
		if component.Scope == "runtime" {
			existing.Scope = "runtime"
		}
		existing.ID = componentID(existing)
		byIdentity[key] = existing
	}

	result := make([]domain.Component, 0, len(byIdentity))
	for _, component := range byIdentity {
		result = append(result, component)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].SourcePath != result[j].SourcePath {
			return result[i].SourcePath < result[j].SourcePath
		}
		if result[i].Name != result[j].Name {
			return result[i].Name < result[j].Name
		}
		if result[i].Version != result[j].Version {
			return result[i].Version < result[j].Version
		}
		return result[i].ID < result[j].ID
	})
	return result
}
