import { createApp, h } from 'vue'
import App from './App.vue'
import AppErrorBoundary from './components/AppErrorBoundary.vue'
import './styles.css'

createApp({ render: () => h(AppErrorBoundary, null, { default: () => h(App) }) }).mount('#app')
