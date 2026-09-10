import { Route, Routes } from 'react-router-dom'

import { ProtectedRoute } from '@/components/ProtectedRoute'
import { AuthProvider } from '@/lib/auth-context'
import { LoginPage } from '@/pages/LoginPage'
import { DashboardPage } from '@/pages/DashboardPage'
import { AlertsPage } from '@/pages/AlertsPage'
import { EventsPage } from '@/pages/EventsPage'
import { ThreatIntelPage } from '@/pages/ThreatIntelPage'
import { VulnerabilitiesPage } from '@/pages/VulnerabilitiesPage'
import { ApiAnalysisPage } from '@/pages/ApiAnalysisPage'
import { PreventionPage } from '@/pages/PreventionPage'
import { ReportsPage } from '@/pages/ReportsPage'
import { NotificationsPage } from '@/pages/NotificationsPage'
import { RetentionPage } from '@/pages/RetentionPage'

function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/" element={<LoginPage />} />
        <Route element={<ProtectedRoute />}>
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/events" element={<EventsPage />} />
          <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
          <Route path="/api-analysis" element={<ApiAnalysisPage />} />
          <Route path="/prevention" element={<PreventionPage />} />
          <Route path="/threat-intel" element={<ThreatIntelPage />} />
          <Route path="/notifications" element={<NotificationsPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/retention" element={<RetentionPage />} />
        </Route>
      </Routes>
    </AuthProvider>
  )
}

export default App
