import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource/noto-sans-arabic/400.css'
import '@fontsource/noto-sans-arabic/600.css'
import '@fontsource/noto-sans-arabic/700.css'
import '@fontsource/noto-kufi-arabic/600.css'
import '@fontsource/noto-kufi-arabic/700.css'
import '@fontsource/jetbrains-mono/400.css'
import '@fontsource/jetbrains-mono/600.css'
import './index.css'
import App from './App.tsx'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
