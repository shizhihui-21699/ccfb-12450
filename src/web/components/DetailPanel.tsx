import { useState } from 'react';
import type { AuditEvent, Finding, FormatHit, RecordDetail, Severity } from '../../shared/types.ts';
import { bytes, timeAgo } from './RecordTable.tsx';

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: '严重',
  high: '高',
  medium: '中',
  low: '低',
  info: '提示'
};

const SEVERITY_CLASS: Record<Severity, string> = {
  critical: 'critical',
  high: 'danger',
  medium: 'warn',
  low: 'info',
  info: 'muted'
};

const CATEGORY_LABEL: Record<string, string> = {
  image: '图像',
  archive: '压缩包',
  document: '文档',
  executable: '可执行',
  audio: '音频',
  video: '视频',
  data: '数据',
  text: '文本',
  unknown: '未知'
};

const ACTION_LABEL: Record<string, string> = {
  upload: '上传',
  release: '放行',
  reject: '拒绝',
  destroy: '清除',
  purge: '到期清除',
  sanitize: '重编码'
};

interface Props {
  record: RecordDetail;
  canReview: boolean;
  onAction: (id: string, action: 'release' | 'reject' | 'destroy', reason: string) => Promise<void>;
}

export function DetailPanel({ record, canReview, onAction }: Props) {
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState<string | null>(null);

  const act = async (action: 'release' | 'reject' | 'destroy') => {
    setBusy(action);
    try {
      await onAction(record.id, action, reason);
      setReason('');
    } finally {
      setBusy(null);
    }
  };

  const isQuarantined = record.status === 'quarantined';
  const canRelease = isQuarantined && record.decision !== 'reject';
  const canDestroy = record.status !== 'destroyed' && record.status !== 'released';

  return (
    <div className="detail">
      <header className="detail-head">
        <div>
          <h2 title={record.fileName}>{record.fileName}</h2>
          <p className="muted">
            {bytes(record.size)} · 上传于 {timeAgo(record.createdAt)} · 判定{' '}
            {record.decision} · 风险分 {record.score}
          </p>
        </div>
        <a className="download" href={`/api/records/${record.id}/original`} download>
          下载原件
        </a>
      </header>

      <section className="block">
        <h3>格式识别</h3>
        <p className="hint">
          以下结论全部来自字节内容。声明的 MIME（{record.declaredMime ?? '无'}）仅作记录。
        </p>
        {record.formats.length === 0 ? (
          <p className="empty">未识别出已知格式。</p>
        ) : (
          <ul className="formats">
            {record.formats.map((f, i) => (
              <FormatRow key={`${f.id}-${f.offsets[0] ?? i}`} hit={f} />
            ))}
          </ul>
        )}
        {record.polyglot && (
          <div className="callout danger">
            <strong>多格式文件</strong>
            <p>
              同一份字节同时满足 {record.polyglotPairs.join('、')} 的全部结构校验。
              这类文件在不同的下游处理链里会被解释成不同的东西，必须人工归类。
            </p>
          </div>
        )}
      </section>

      {record.image && (
        <section className="block">
          <h3>图像</h3>
          <dl className="kv">
            <dt>格式</dt>
            <dd>{record.image.format.toUpperCase()}</dd>
            <dt>尺寸</dt>
            <dd>
              {record.image.width ?? '?'} × {record.image.height ?? '?'}
              {record.image.frames > 1 ? ` · ${record.image.frames} 帧` : ''}
            </dd>
            <dt>容器结束</dt>
            <dd>{bytes(record.image.declaredEnd)}</dd>
            <dt>尾部多余数据</dt>
            <dd className={record.image.trailingBytes > 0 ? 'danger-text' : ''}>
              {bytes(record.image.trailingBytes)}
            </dd>
            <dt>元数据</dt>
            <dd>{record.image.metadata.length > 0 ? record.image.metadata.join('、') : '无'}</dd>
            <dt>清洗方式</dt>
            <dd>{record.image.sanitizer === 'reencode' ? '按像素重编码' : record.image.sanitizer === 'rewrite' ? '重写容器' : '不支持'}</dd>
          </dl>
          {record.sanitizedSha256 && (
            <a className="download" href={`/api/records/${record.id}/clean`} download>
              下载清洗产物
            </a>
          )}
        </section>
      )}

      {record.archive && (
        <section className="block">
          <h3>压缩包预检</h3>
          <p className="hint">以下数值由网关实际测量得出，不采信目录中声明的大小。</p>
          <dl className="kv">
            <dt>容器</dt>
            <dd>{record.archive.format.toUpperCase()}</dd>
            <dt>条目数</dt>
            <dd>{record.archive.entryCount}</dd>
            <dt>预估解压后</dt>
            <dd>{bytes(record.archive.estimatedTotalExpandedBytes)}</dd>
            <dt>压缩比</dt>
            <dd>
              {record.archive.estimatedTotalExpandedBytes >= 1024
                ? `${record.archive.compressionRatio.toFixed(1)}:1`
                : '不适用（解压后不足 1 KiB）'}
            </dd>
            <dt>嵌套层数</dt>
            <dd className={record.archive.depth > record.limits.maxArchiveDepth ? 'danger-text' : ''}>
              {record.archive.depth} / 上限 {record.limits.maxArchiveDepth}
            </dd>
            <dt>加密条目</dt>
            <dd>{record.archive.encryptedEntries}</dd>
          </dl>
          {record.archive.pathTraversalEntries.length > 0 && (
            <div className="callout danger">
              <strong>路径穿越条目</strong>
              <p>{record.archive.pathTraversalEntries.join('、')}</p>
            </div>
          )}
          {record.archive.nestedArchives.length > 0 && (
            <details>
              <summary>嵌套压缩包 {record.archive.nestedArchives.length} 个</summary>
              <ul className="plain">
                {record.archive.nestedArchives.slice(0, 20).map((n, i) => (
                  <li key={`${n.name}-${i}`}>
                    <code>{n.name}</code> → {n.format}
                  </li>
                ))}
              </ul>
            </details>
          )}
          {record.archive.sample.length > 0 && (
            <details>
              <summary>条目样例</summary>
              <table className="mini">
                <thead>
                  <tr>
                    <th>名称</th>
                    <th>压缩后</th>
                    <th>解压后</th>
                    <th>方法</th>
                  </tr>
                </thead>
                <tbody>
                  {record.archive.sample.map((e, i) => (
                    <tr key={`${e.name}-${i}`}>
                      <td title={e.name}>{e.name}</td>
                      <td className="num">{bytes(e.compressedSize)}</td>
                      <td className="num">{bytes(e.uncompressedSize)}</td>
                      <td>{e.method === 0 ? '存储' : e.method === 8 ? 'deflate' : e.method}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </details>
          )}
        </section>
      )}

      <section className="block">
        <h3>判定依据</h3>
        {record.findings.length === 0 ? (
          <p className="empty">没有触发任何规则。</p>
        ) : (
          <ul className="findings">
            {record.findings.map((f, i) => (
              <FindingRow key={`${f.code}-${i}`} finding={f} />
            ))}
          </ul>
        )}
      </section>

      <section className="block">
        <h3>本次生效上限</h3>
        <dl className="kv compact">
          <dt>单文件</dt>
          <dd>{bytes(record.limits.maxUploadBytes)}</dd>
          <dt>解压总量</dt>
          <dd>{bytes(record.limits.maxExpandedBytes)}</dd>
          <dt>压缩比</dt>
          <dd>{record.limits.rejectCompressionRatio}:1</dd>
          <dt>嵌套层数</dt>
          <dd>{record.limits.maxArchiveDepth}</dd>
          <dt>像素</dt>
          <dd>{new Intl.NumberFormat('zh-CN').format(record.limits.maxImagePixels)}</dd>
        </dl>
      </section>

      <section className="block">
        <h3>复查</h3>
        {record.reviewedBy && (
          <p className="muted">
            由 {record.reviewedBy} 于 {timeAgo(record.reviewedAt ?? record.updatedAt)} 处理
            {record.reviewReason ? `：${record.reviewReason}` : ''}
          </p>
        )}
        {isQuarantined ? (
          <>
            <label className="field">
              <span>处理说明（记入审计）</span>
              <textarea
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                rows={3}
                maxLength={500}
                placeholder="例如：确认为素材包，已核对来源工单 #1234"
              />
            </label>
            <div className="actions">
              <button
                className="btn ok"
                disabled={!canReview || !canRelease || busy !== null}
                onClick={() => void act('release')}
                title={!canReview ? '需要先填写审核人' : undefined}
              >
                {busy === 'release' ? '处理中…' : '放行'}
              </button>
              <button
                className="btn danger"
                disabled={!canReview || busy !== null}
                onClick={() => void act('reject')}
              >
                {busy === 'reject' ? '处理中…' : '拒绝'}
              </button>
              <button
                className="btn ghost"
                disabled={!canReview || !canDestroy || busy !== null}
                onClick={() => void act('destroy')}
              >
                {busy === 'destroy' ? '处理中…' : '清除原始数据'}
              </button>
            </div>
            {!canReview && <p className="hint">放行、拒绝或清除都需要先填写审核人身份。</p>}
            {!canRelease && (
              <p className="hint">该文件被判为拒绝，放行操作不适用于它。如确属误判，请从上游重新提交。</p>
            )}
          </>
        ) : (
          <p className="muted">该记录不处于待复查状态，无需操作。</p>
        )}
      </section>

      <section className="block">
        <h3>审计记录</h3>
        <ul className="audit">
          {record.audit.map((a, i) => (
            <AuditRow key={i} event={a} />
          ))}
        </ul>
      </section>
    </div>
  );
}

function FormatRow({ hit }: { hit: FormatHit }) {
  return (
    <li className="format">
      <div className="format-main">
        <strong>{hit.label}</strong>
        <span className={`tag ${hit.evidence === 'structural' || hit.evidence === 'textual' ? 'ok' : 'warn'}`}>
          {hit.evidence === 'structural' ? '结构校验' : hit.evidence === 'textual' ? '文本解析' : '仅魔数'}
        </span>
        <span className="tag muted">{CATEGORY_LABEL[hit.category] ?? hit.category}</span>
      </div>
      <div className="format-meta">
        起点 {hit.offsets.join(', ')}
        {hit.endOffset !== null ? ` · 结束 ${hit.endOffset}` : ''}
        {hit.detail ? ` · ${hit.detail}` : ''}
      </div>
    </li>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  return (
    <li className={`finding ${SEVERITY_CLASS[finding.severity]}`}>
      <div className="finding-head">
        <span className={`pill ${SEVERITY_CLASS[finding.severity]}`}>
          {SEVERITY_LABEL[finding.severity]}
        </span>
        <code className="finding-code">{finding.code}</code>
      </div>
      <p>{finding.message}</p>
      {finding.data && (
        <dl className="finding-data">
          {Object.entries(finding.data).map(([k, v]) => (
            <span key={k}>
              <dt>{k}</dt>
              <dd>{String(v)}</dd>
            </span>
          ))}
        </dl>
      )}
    </li>
  );
}

function AuditRow({ event }: { event: AuditEvent }) {
  return (
    <li>
      <span className="audit-action">{ACTION_LABEL[event.action] ?? event.action}</span>
      <span className="audit-actor">{event.actor}</span>
      <span className="muted">{timeAgo(event.at)}</span>
      {event.detail && <span className="audit-detail">{event.detail}</span>}
    </li>
  );
}
