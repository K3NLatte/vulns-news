package repository

import (
	"strings"
	"testing"
)

func TestAmbiguousLanguageFilename(t *testing.T) {
	for _, name := range []string{"hello.m", "rtl/chip.v", "src/Main.AS", "kernel.cl", "Account.cls", "project.pro", "Hello.mod", "go.mod"} {
		if !ambiguousLanguageFilename(name) {
			t.Errorf("ambiguousLanguageFilename(%q) = false", name)
		}
	}
	for _, name := range []string{"", "m", "script.pl", "script.PL", "header.h", "main.go", "main.m.bak", "main.m/README", "main.vlang"} {
		if ambiguousLanguageFilename(name) {
			t.Errorf("ambiguousLanguageFilename(%q) = true", name)
		}
	}
}

func TestLanguageFromContent(t *testing.T) {
	tests := []struct {
		title, name, text, want string
	}{
		{"objective implementation", "Thing.m", "#import <Foundation/Foundation.h>\n@implementation Thing\n- (void)run {}\n@end", "Objective-C"},
		{"objective interface prefix", "Thing.m", "@interface Thing : NSObject\n", "Objective-C"},
		{"matlab function", "square.m", "function y = square(x)\ny = x.^2;\nend", "MATLAB"},
		{"matlab outputs", "split.m", "function [a, b] = split(x)\na = x; b = x;\nend", "MATLAB"},
		{"matlab no output", "hello.m", "function hello()\ndisp('hello');\nend", "MATLAB"},
		{"matlab class", "Thing.m", "classdef Thing < handle\nproperties\nx\nend\nend", "MATLAB"},
		{"octave function", "square.m", "function y = square(x)\ny = x.^2;\nendfunction", "Octave"},
		{"octave cleanup", "cleanup.m", "unwind_protect\n  work();\nunwind_protect_cleanup\n  cleanup();\nend_unwind_protect", "Octave"},
		{"mercury module", "hello.m", ":- module hello.\n:- interface.\n:- import_module io.\n:- pred main(io::di, io::uo) is det.\n:- implementation.", "Mercury"},
		{"verilog module", "counter.v", "module counter(input clk, output reg q);\nalways @(posedge clk) q <= ~q;\nendmodule", "Verilog"},
		{"verilog parameters", "counter.v", "module counter #(parameter N = 8) (input clk);\nendmodule", "Verilog"},
		{"verilog compact", "empty.v", "module empty; endmodule", "Verilog"},
		{"coq require", "proof.v", "Require Import Coq.Lists.List.", "Coq / Rocq"},
		{"rocq require list", "proof.v", "From Stdlib Require Import List Arith.", "Coq / Rocq"},
		{"coq theorem", "proof.v", "Theorem identity : forall P : Prop, P -> P.\nProof. intros P p. exact p. Qed.", "Coq / Rocq"},
		{"coq definition", "proof.v", "Definition answer : nat := 42.", "Coq / Rocq"},
		{"v module", "main.v", "module main\nimport os\nfn main() {\n println(os.args)\n}", "V"},
		{"v implicit module", "main.v", "fn main() { println('hello') }", "V"},
		{"actionscript package", "Main.as", "package example {\n public class Main extends Sprite {\n }\n}", "ActionScript"},
		{"actionscript function", "Main.as", "public function greet(name:String):void {\n trace(name);\n}", "ActionScript"},
		{"angelscript handle", "Main.as", "Entity@ entity = getEntity();", "AngelScript"},
		{"angelscript reference", "Main.as", "void greet(const string &in name) {\n print(name);\n}", "AngelScript"},
		{"common lisp", "example.cl", "(defun square (x)\n (* x x))", "Common Lisp"},
		{"common lisp uppercase", "example.cl", "(IN-PACKAGE :CL-USER)", "Common Lisp"},
		{"opencl kernel", "add.cl", "__kernel void add(__global float *data) {\n data[get_global_id(0)] += 1;\n}", "OpenCL"},
		{"opencl unprefixed", "add.cl", "kernel void add(global float *data) {}", "OpenCL"},
		{"apex sharing", "Account.cls", "public with sharing class AccountController {\n}", "Apex"},
		{"apex test", "Account.cls", "@isTest\nprivate class AccountTest {\n}", "Apex"},
		{"apex rest", "Account.cls", "@RestResource(urlMapping='/accounts/*')\nglobal class Accounts {\n}", "Apex"},
		{"prolog directive", "family.pro", ":- module(family, [parent/2]).\nparent(alice, bob).", "Prolog"},
		{"prolog rule", "family.pro", "ancestor(X, Y) :- parent(X, Y).", "Prolog"},
		{"prolog multiline rule", "family.pro", "ancestor(X, Y) :-\n parent(X, Z),\n ancestor(Z, Y).", "Prolog"},
		{"qmake template", "app.pro", "TEMPLATE = app\nTARGET = hello\nSOURCES += main.cpp", "QMake"},
		{"qmake qt", "app.pro", "QT += widgets\nSOURCES += main.cpp", "QMake"},
		{"modula program", "Hello.mod", "MODULE Hello;\nFROM InOut IMPORT WriteString;\nBEGIN\n WriteString('Hello');\nEND Hello.", "Modula-2"},
		{"modula implementation", "Stack.mod", "IMPLEMENTATION MODULE Stack;\nBEGIN\nEND Stack.", "Modula-2"},
		{"uppercase suffix bom crlf", "src/Thing.M", "\xef\xbb\xbf  @implementation Thing\r\n@end\r\n", "Objective-C"},
		{"nil equivalent", "empty.m", "", ""},
		{"generic m script", "script.m", "x = 1;\nplot(x);", ""},
		{"weak v module", "main.v", "module main", ""},
		{"weak as c syntax", "main.as", "void main() { print(1); }", ""},
		{"generic cl c", "main.cl", "int main() { return 0; }", ""},
		{"generic class", "Main.cls", "public class Main { }", ""},
		{"vb class", "Main.cls", "VERSION 1.0 CLASS\nBEGIN\n MultiUse = -1\nEND\nPublic Sub Run()\nEnd Sub", ""},
		{"latex class", "Main.cls", "\\NeedsTeXFormat{LaTeX2e}\n\\ProvidesClass{Main}\n", ""},
		{"prolog facts weak", "family.pro", "parent(alice, bob).", ""},
		{"qmake weak", "app.pro", "CONFIG += release", ""},
		{"idl pro", "image.pro", "PRO image, x\n PRINT, x\nEND", ""},
		{"go module", "go.mod", "module example.org/app\ngo 1.25", ""},
		{"go module reserved filename", "sub/GO.MOD", "MODULE Hello;\nBEGIN\nEND Hello.", ""},
		{"unknown mod", "model.mod", "module example.org/app\ngo 1.25", ""},
		{"weak modula", "Hello.mod", "MODULE Hello;", ""},
		{"perl unchanged", "family.pl", ":- module(family, [parent/2]).", ""},
		{"unsupported suffix", "main.txt", "@implementation Thing\n@end", ""},
		{"binary", "Thing.m", "@implementation Thing\n@end\x00", ""},
		{"not anchored", "Thing.m", "documentation: @implementation Thing\n@end", ""},
		{"not keyword", "Thing.m", "@implementationDetails Thing", ""},
		{"m conflict", "mixed.m", "@implementation Thing\n@end\nfunction y = square(x)\nend", ""},
		{"mercury octave conflict", "mixed.m", ":- module mixed.\n:- interface.\nfunction y = f(x)\nendfunction", ""},
		{"v conflict", "mixed.v", "module hardware();\nendmodule\nfn main() {}", ""},
		{"coq verilog conflict", "mixed.v", "Require Import List.\nmodule hardware();\nendmodule", ""},
		{"as conflict", "mixed.as", "public function run():void {}\nEntity@ entity;", ""},
		{"cl conflict", "mixed.cl", "(defun foo () 1)\n__kernel void foo() {}", ""},
		{"pro conflict", "mixed.pro", ":- use_module(library(lists)).\nTEMPLATE = app", ""},
		{"duplicate evidence same language", "square.m", "function y = square(x)\nend\nfunction hello()\nend", "MATLAB"},
	}
	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			if got := languageFromContent(tt.name, []byte(tt.text)); got != tt.want {
				t.Errorf("languageFromContent(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestLanguageFromContentCommentsAndStrings(t *testing.T) {
	tests := []struct{ name, text, want string }{
		{"comment.m", "// @implementation Thing\n// @end", ""},
		{"comment.m", "/*\n@implementation Thing\n@end\n*/", ""},
		{"comment.m", "%{\nfunction y = f(x)\n%}\n", ""},
		{"comment.m", "#{\nfunction y = f(x)\nendfunction\n#}\n", ""},
		{"comment.m", "% function y = f(x)\n# endfunction", ""},
		{"comment.v", "(* outer (* nested *)\nRequire Import List.\n*)", ""},
		{"comment.mod", "(*\nMODULE Hello;\nBEGIN\nEND Hello.\n*)", ""},
		{"comment.cl", "; (defun foo () 1)\n; __kernel void foo() {}", ""},
		{"comment.cl", "#| outer #| nested |#\n(defun foo () 1)\n|#", ""},
		{"comment.pro", "% ancestor(X,Y) :- parent(X,Y).\n# TEMPLATE = app", ""},
		{"comment.as", "/*\nEntity@ entity;\n*/\n// public function run():void {}", ""},
		{"comment.cls", "/*\npublic with sharing class Thing {}\n*/", ""},
		{"comment.m", "/* unterminated\n@implementation Thing\n@end", ""},
		{"literal.m", "\"\n@implementation Thing\n@end\n\"", ""},
		{"literal.v", "`\nRequire Import List.\n`", ""},
		{"literal.as", "string text = \"Entity@ entity;\";", ""},
		{"literal.m", "\"not code\" @implementation Thing", ""},
		{"real.m", "/* @implementation Fake */\nfunction y = f(x) % comment\ny = x';\nend", "MATLAB"},
		{"real.v", "(* Require Import Fake. *)\nmodule counter(); // real module\nendmodule", "Verilog"},
		{"real.cl", "/* (defun fake () 1) */\n__kernel void real() {}", "OpenCL"},
		{"real.pro", "# project comment\nTEMPLATE = app # application", "QMake"},
		{"real.m", "% Header\n/* header */ @implementation Thing\n@end", "Objective-C"},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/"+tt.text, func(t *testing.T) {
			if got := languageFromContent(tt.name, []byte(tt.text)); got != tt.want {
				t.Errorf("languageFromContent = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLanguageFromContentBoundedPrefix(t *testing.T) {
	padding := strings.Repeat(" \n", languageContentLimit/2)
	if got := languageFromContent("late.m", []byte(padding+"@implementation Late")); got != "" {
		t.Fatalf("signature beyond prefix limit detected as %q", got)
	}
	text := "@implementation Early\n" + padding + "function y = late(x)\n"
	prefix := []byte(text)
	before := string(prefix)
	if got := languageFromContent("early.m", prefix); got != "Objective-C" {
		t.Errorf("early signature = %q, want Objective-C", got)
	}
	if string(prefix) != before {
		t.Error("detector mutated caller's prefix")
	}
	text = strings.Repeat(" ", languageContentLimit-10) + "@implementation Late"
	if got := languageFromContent("partial.m", []byte(text)); got != "" {
		t.Errorf("partial line detected as %q", got)
	}
	if got := languageFromContent("empty.m", nil); got != "" {
		t.Errorf("nil prefix detected as %q", got)
	}
}
