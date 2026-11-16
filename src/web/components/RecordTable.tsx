import type { RecordStatus, RecordSummary } from '../../shared/types.ts';

const STATUS_LABEL: Record<RecordStatus, string> = {
  accepted: '已接收',
  quarantined: '待复查',
  rejected: '已拒绝',
  released: '已放行',
  destroyed: '已清除'
};

const DECISION_LABEL: Record<RecordSummary['decision'], string> = {
  accept: '接收',
  sanitize: '清洗',
  quarantine: '隔离',
  reject: '拒绝'
};

const SEVERITY_BY_STATUS: Record<RecordStatus, string> = {
  accepted: 'ok',
  quarantined: 'warn',
  rejected: 'danger',
  released: 'ok',
  destroyed: 'muted'
};

export function bytes(n: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

export function timeAgo(iso: string): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return '—';
  const s = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (s < 60) return `${s} 秒前`;
  if (s < 3600) return `${Math.round(s / 60)} 分钟前`;
  if (s < 86400) return `${Math.round(s / 3600)} 小时前`;
  return `${Math.round(s / 86400)} 天前`;
}

interface Props {
  records: RecordSummary[];
  selectedId: string | null;
  onOpen: (id: string) => void;
  loading: boolean;
}

export function RecordTable({ records, selectedId, onOpen, loading }: Props) {
  if (loading) return <p className="empty">加载中…</p>;
  if (records.length === 0) return null;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>文件</th>
            <th>判定</th>
            <th className="col-mid">内容</th>
            <th className="col-num">大小</th>
            <th>时间</th>
          </tr>
        </thead>
        <tbody>
          {records.map((r) => (
            <tr
              key={r.id}
              className={r.id === selectedId ? 'row selected' : 'row'}
              onClick={() => onOpen(r.id)}
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter') onOpen(r.id);
              }}
            >
              <td className="cell-name">
                <span className="filename" title={r.fileName}>
                  {r.fileName}
                </span>
                {r.polyglot && (
                  <span className="tag danger" title="同一份内容同时是多种格式">
                    多格式
                  </span>
                )}
                {r.sanitizedSize !== null && (
                  <span className="tag ok" title="已生成清洗后的产物">
                    已清洗
                  </span>
                )}
              </td>
              <td>
                <span className={`pill ${SEVERITY_BY_STATUS[r.status]}`}>{STATUS_LABEL[r.status]}</span>
                <span className="decision">{DECISION_LABEL[r.decision]}</span>
              </td>
              <td className="cell-summary col-mid" title={r.summary}>
                {r.primaryFormat?.label ?? '未识别'}
              </td>
              <td className="num col-num">{bytes(r.size)}</td>
              <td className="cell-time muted">{timeAgo(r.createdAt)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
