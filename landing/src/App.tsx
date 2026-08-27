import { BackgroundGlow } from '@/components/background-glow'
import { Nav } from '@/components/nav'
import { Hero } from '@/components/hero'
import { WhyMonitor } from '@/components/why-monitor'
import { Pipeline } from '@/components/pipeline'
import { UseCases } from '@/components/use-cases'
import { ClosingCta } from '@/components/closing-cta'
import { Footer } from '@/components/footer'

function App() {
  return (
    <div className="relative min-h-screen">
      <BackgroundGlow />
      <Nav />
      <main>
        <Hero />
        <WhyMonitor />
        <Pipeline />
        <UseCases />
        <ClosingCta />
      </main>
      <Footer />
    </div>
  )
}

export default App
