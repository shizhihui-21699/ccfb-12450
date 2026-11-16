import type { Stats } from '../../shared/types.ts';

const fmt = (n: number) => new Intl.NumberFormat('zh-CN').format(n);

function bytes(n: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

export function StatsBar({ stats }: { stats: Stats }) {
  const items: Array<{ label: string; value: string; tone?: string }> = [
    { label: '累计上传', value: fmt(stats.total) },
    { label: '待复查', value: fmt(stats.quarantined), tone: stats.quarantined > 0 ? 'warn' : '' },
    { label: '已接收', value: fmt(stats.accepted) },
    { label: '已放行', value: fmt(stats.released) },
    { label: '已拒绝', value: fmt(stats.rejected), tone: stats.rejected > 0 ? 'danger' : '' },
    { label: '多格式', value: fmt(stats.polyglot), tone: stats.polyglot > 0 ? 'warn' : '' },
    { label: '清洗产物', value: fmt(stats.sanitized) },
    { label: '入库体积', value: bytes(stats.bytesIn) }
  ];
  return (
    <div className="stats">
      {items.map((it) => (
        <div key={it.label} className={`stat ${it.tone ?? ''}`}>
          <span className="stat-value">{it.value}</span>
          <span className="stat-label">{it.label}</span>
        </div>
      ))}
    </div>
  );
}
