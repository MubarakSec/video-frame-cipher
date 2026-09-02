import { LabView } from './views/LabView'

function App() {
  return (
    <div className="app app--lab">
      <a className="skip-link" href="#main-content">
        انتقل إلى المحتوى
      </a>

      <main id="main-content">
        <LabView />
      </main>
    </div>
  )
}

export default App
