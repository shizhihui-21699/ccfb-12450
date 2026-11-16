import { useCallback, useEffect, useMemo, useState } from 'react';
import type {
  Limits,
  RecordDetail,
  RecordStatus,
  RecordSummary,
  Stats,
  UploadResponse
} from '../shared/types.ts';
import { RecordTable } from './components/RecordTable.tsx';
import { DetailPanel } from './components/DetailPanel.tsx';
import { UploadPanel } from './components/UploadPanel.tsx';
import { StatsBar } from './components/StatsBar.tsx';
import { LimitsPanel } from './components/LimitsPanel.tsx';

const REVIEWER_STORAGE_KEY = 'filegate.reviewer';

type Tab = 'queue' | 'all' | 'accepted' | 'rejected' | 'limits';

const TABS: Array<{ id: Tab; label: string; status?: RecordStatus }> = [
  { id: 'queue', label: '待复查', status: 'quarantined' },
  { id: 'all', label: '全部', status: undefined },
  { id: 'accepted', label: '已放行', status: 'accepted' },
  { id: 'rejected', label: '已拒绝', status: 'rejected' },
  { id: 'limits', label: '策略上限' }
];

export function App() {
  const [tab, setTab] = useState<Tab>('queue');
  const [records, setRecords] = useState<RecordSummary[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [limits, setLimits] = useState<Limits | null>(null);
  const [selected, setSelected] = useState<RecordDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reviewer, setReviewer] = useState<string>(() => {
    try {
      return localStorage.getItem(REVIEWER_STORAGE_KEY) ?? '';
    } catch {
      return '';
    }
  });
  const [toast, setToast] = useState<string | null>(null);

  const rememberReviewer = (name: string) => {
    setReviewer(name);
    try {
      localStorage.setItem(REVIEWER_STORAGE_KEY, name);
    } catch {
      /* private mode: the field still works for this session */
    }
  };

  const authHeaders = useMemo<Record<string, string>>(() => {
    const name = reviewer.trim();
    const headers: Record<string, string> = {};
    if (name) headers['x-reviewer'] = name;
    return headers;
  }, [reviewer]);

  const loadStats = useCallback(async () => {
    try {
      const res = await fetch('/api/stats');
      if (res.ok) setStats((await res.json()) as Stats);
    } catch {
      /* the list is the primary view; a missing stat is not fatal */
    }
  }, []);

  const loadLimits = useCallback(async () => {
    try {
      const res = await fetch('/api/health');
      if (res.ok) {
        const body = (await res.json()) as { limits: Limits };
        setLimits(body.limits);
      }
    } catch {
      /* shown as "unknown" in the panel */
    }
  }, []);

  const loadRecords = useCallback(
    async (cursor?: string) => {
      const def = TABS.find((t) => t.id === tab);
      if (!def || tab === 'limits') return;
      setLoading(true);
      setError(null);
      try {
        const params = new URLSearchParams({ limit: '50' });
        if (def.status) params.set('status', def.status);
        if (cursor) params.set('cursor', cursor);
        const res = await fetch(`/api/records?${params.toString()}`);
        if (!res.ok) throw new Error(`列表加载失败 (${res.status})`);
        const page = (await res.json()) as { records: RecordSummary[]; nextCursor: string | null };
        setRecords((prev) => (cursor ? [...prev, ...page.records] : page.records));
        setNextCursor(page.nextCursor);
      } catch (e) {
        setError((e as Error).message);
      } finally {
        setLoading(false);
      }
    },
    [tab]
  );

  useEffect(() => {
    void loadStats();
    void loadLimits();
  }, [loadStats, loadLimits]);

  useEffect(() => {
    setRecords([]);
    setNextCursor(null);
    setSelected(null);
    void loadRecords();
  }, [loadRecords]);

  // A `?record=<id>` deep link makes a record linkable from a ticket or chat.
  // Read once on mount; the list selection then drives the panel as usual.
  useEffect(() => {
    const wanted = new URLSearchParams(location.search).get('record');
    if (wanted) void openRecord(wanted);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const openRecord = async (id: string) => {
    try {
      const res = await fetch(`/api/records/${id}`);
      if (!res.ok) throw new Error(`记录加载失败 (${res.status})`);
      setSelected((await res.json()) as RecordDetail);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const review = async (id: string, action: 'release' | 'reject' | 'destroy', reason: string) => {
    if (!reviewer.trim()) {
      setError('请先在右上角填写审核人身份');
      return;
    }
    setError(null);
    try {
      const res = await fetch(`/api/records/${id}/${action}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...authHeaders },
        body: JSON.stringify({ reason })
      });
      const body = (await res.json()) as { record?: RecordDetail; error?: string };
      if (!res.ok) throw new Error(body.error ?? `操作失败 (${res.status})`);
      setToast(
        action === 'release' ? '已放行' : action === 'reject' ? '已拒绝' : '原始数据已清除'
      );
      if (body.record) setSelected(body.record);
      await loadRecords();
      await loadStats();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const onUploaded = async (result: UploadResponse) => {
    const accepted = result.records.filter((r) => r.status === 'accepted').length;
    const quarantined = result.records.filter((r) => r.status === 'quarantined').length;
    const rejectedCount = result.records.filter((r) => r.status === 'rejected').length;
    const parts = [
      accepted > 0 ? `${accepted} 个已接收` : '',
      quarantined > 0 ? `${quarantined} 个隔离待复查` : '',
      rejectedCount > 0 ? `${rejectedCount} 个拒绝` : '',
      result.rejected.length > 0 ? `${result.rejected.length} 个上传被拒` : ''
    ].filter(Boolean);
    setToast(parts.join('，') || '没有文件');
    await loadRecords();
    await loadStats();
  };

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 4000);
    return () => clearTimeout(t);
  }, [toast]);

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            FG
          </span>
          <div>
            <h1>上传安检网关</h1>
            <p>按内容识别格式 · 多格式检测 · 压缩包预检 · 图像净化</p>
          </div>
        </div>
        <label className="reviewer">
          <span>审核人</span>
          <input
            value={reviewer}
            onChange={(e) => rememberReviewer(e.target.value)}
            placeholder="工号或邮箱"
            autoComplete="username"
            maxLength={64}
          />
        </label>
      </header>

      {stats && <StatsBar stats={stats} />}

      <main className="layout">
        <section className="panel upload-panel">
          <UploadPanel onUploaded={onUploaded} authHeaders={authHeaders} />
        </section>

        <section className="panel list-panel">
          <nav className="tabs" role="tablist">
            {TABS.map((t) => (
              <button
                key={t.id}
                role="tab"
                aria-selected={tab === t.id}
                className={tab === t.id ? 'tab active' : 'tab'}
                onClick={() => setTab(t.id)}
              >
                {t.label}
                {t.id === 'queue' && stats && stats.quarantined > 0 && (
                  <span className="badge">{stats.quarantined}</span>
                )}
              </button>
            ))}
          </nav>

          {error && (
            <div className="alert" role="alert">
              {error}
            </div>
          )}

          {tab === 'limits' ? (
            <LimitsPanel limits={limits} />
          ) : (
            <>
              <RecordTable
                records={records}
                selectedId={selected?.id ?? null}
                onOpen={openRecord}
                loading={loading && records.length === 0}
              />
              {nextCursor && (
                <button className="more" onClick={() => loadRecords(nextCursor)} disabled={loading}>
                  {loading ? '加载中…' : '加载更多'}
                </button>
              )}
              {!loading && records.length === 0 && (
                <p className="empty">此分类下没有记录。</p>
              )}
            </>
          )}
        </section>

        <section className="panel detail-panel">
          {selected ? (
            <DetailPanel
              record={selected}
              canReview={Boolean(reviewer.trim())}
              onAction={review}
            />
          ) : (
            <div className="placeholder">
              <p>选择左侧一条记录查看完整判定依据。</p>
            </div>
          )}
        </section>
      </main>

      {toast && (
        <div className="toast" role="status">
          {toast}
        </div>
      )}
    </div>
  );
}
