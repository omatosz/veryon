import { Route, Routes } from 'react-router-dom'

import { ProtectedRoute } from '@/components/ProtectedRoute'
import { AuthProvider } from '@/lib/auth-context'
import { LoginPage } from '@/pages/LoginPage'
import { DashboardPage } from '@/pages/DashboardPage'
import { AlertsPage } from '@/pages/AlertsPage'
import { EventsPage } from '@/pages/EventsPage'
import { ThreatIntelPage } from '@/pages/ThreatIntelPage'
import { ReportsPage } from '@/pages/ReportsPage'

function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/" element={<LoginPage />} />
        <Route element={<ProtectedRoute />}>
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/events" element={<EventsPage />} />
          <Route path="/threat-intel" element={<ThreatIntelPage />} />
          <Route path="/reports" element={<ReportsPage />} />
        </Route>
      </Routes>
    </AuthProvider>
  )
}

export default App
