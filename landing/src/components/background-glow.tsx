export function BackgroundGlow() {
  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 -z-10 overflow-hidden bg-background">
      <div className="glow-blob absolute left-[8%] top-[-10%] h-[36rem] w-[36rem] rounded-full bg-[#36255C] opacity-40 blur-[120px]" />
      <div className="glow-blob-slow absolute right-[-6%] top-[18%] h-[30rem] w-[30rem] rounded-full bg-[#A78BFA] opacity-[0.14] blur-[130px]" />
      <div className="glow-blob absolute bottom-[-14%] left-[22%] h-[34rem] w-[34rem] rounded-full bg-[#23212C] opacity-60 blur-[110px]" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,rgba(20,19,26,0)_0%,rgba(20,19,26,0.6)_70%,rgba(20,19,26,0.95)_100%)]" />
    </div>
  )
}
