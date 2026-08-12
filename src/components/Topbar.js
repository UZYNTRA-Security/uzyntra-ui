export default function Topbar() {
  return (
    <header className="border-b border-slate-200/80 bg-white/90 px-6 py-4 backdrop-blur">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-base font-semibold text-slate-950">
            UZYNTRA Command Center
          </p>
          <p className="text-sm text-slate-600">
            Advanced API Threat Intelligence &amp; Control
          </p>
        </div>

        <div className="rounded-full border border-slate-200 bg-slate-50 px-4 py-2 text-xs font-semibold text-slate-600">
          Admin API: /api/admin
        </div>
      </div>
    </header>
  );
}
