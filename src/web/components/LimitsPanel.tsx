import type { Limits } from '../../shared/types.ts';
import { bytes } from './RecordTable.tsx';

const ENV: Record<keyof Limits, string> = {
  maxUploadBytes: 'FILEGATE_MAX_UPLOAD_BYTES',
  maxArchiveEntries: 'FILEGATE_MAX_ARCHIVE_ENTRIES',
  maxArchiveDepth: 'FILEGATE_MAX_ARCHIVE_DEPTH',
  maxExpandedBytes: 'FILEGATE_MAX_EXPANDED_BYTES',
  rejectCompressionRatio: 'FILEGATE_REJECT_RATIO',
  quarantineCompressionRatio: 'FILEGATE_QUARANTINE_RATIO',
  maxImagePixels: 'FILEGATE_MAX_IMAGE_PIXELS',
  maxImageDimension: 'FILEGATE_MAX_IMAGE_DIMENSION',
  maxTrailingBytes: 'FILEGATE_MAX_TRAILING_BYTES',
  maxNestedArchiveProbes: 'FILEGATE_MAX_NESTED_PROBES',
  maxTextScanBytes: 'FILEGATE_MAX_TEXT_SCAN_BYTES',
  maxEmbeddedScanBytes: 'FILEGATE_MAX_EMBEDDED_SCAN_BYTES',
  scanTimeoutMs: 'FILEGATE_SCAN_TIMEOUT_MS',
  retentionDays: 'FILEGATE_RETENTION_DAYS',
  allowExecutables: 'FILEGATE_ALLOW_EXECUTABLES'
};

const SIZE_KEYS = new Set<keyof Limits>([
  'maxUploadBytes',
  'maxExpandedBytes',
  'maxTextScanBytes',
  'maxEmbeddedScanBytes'
]);

const REASON: Record<keyof Limits, string> = {
  maxUploadBytes: '原始上传上限。再大的源素材应走离线通道。',
  maxArchiveEntries: '单个压缩包的条目上限，防止海量小文件拖垮解包。',
  maxArchiveDepth: '压缩包套压缩包的层数上限。正常素材不会超过两层。',
  maxExpandedBytes: '所有层级累计解压出的字节上限，是防炸弹的硬指标。',
  rejectCompressionRatio: '高于此压缩比视为炸弹特征，直接隔离。',
  quarantineCompressionRatio: '高于此值但未到拒绝线的，交人工判断。',
  maxImagePixels: '解码后的像素上限，40MP 已覆盖 8000×5000。',
  maxImageDimension: '单边像素上限，防止超长条带图片。',
  maxTrailingBytes: '容器结束标记之后允许的字节数，正常编码器为 0。',
  maxNestedArchiveProbes: '每层最多探测多少个条目是否为嵌套压缩包。',
  maxTextScanBytes: '文本/JSON 解析的字节上限。',
  maxEmbeddedScanBytes: '寻找第二种格式时最多向前读取的字节数。',
  scanTimeoutMs: '单个文件的扫描墙钟上限，超时按隔离处理。',
  retentionDays: '隔离区数据保留天数，到期自动清除。',
  allowExecutables: '是否允许可执行文件通过（默认拒绝）。'
};

export function LimitsPanel({ limits }: { limits: Limits | null }) {
  if (!limits) return <p className="empty">无法读取当前上限。</p>;
  const keys = Object.keys(limits) as Array<keyof Limits>;
  return (
    <div className="limits">
      <p className="hint">
        以下是本次运行实际生效的默认值。可通过环境变量覆盖，修改后需重启服务。
      </p>
      <table className="mini limits-table">
        <thead>
          <tr>
            <th>项目</th>
            <th>生效值</th>
            <th>环境变量</th>
          </tr>
        </thead>
        <tbody>
          {keys.map((k) => {
            const v = limits[k];
            const shown = typeof v === 'boolean' ? (v ? '允许' : '禁止') : SIZE_KEYS.has(k) ? bytes(v as number) : String(v);
            return (
              <tr key={k}>
                <td>
                  <strong>{REASON[k]}</strong>
                  <div className="muted small">{k}</div>
                </td>
                <td className="num">{shown}</td>
                <td>
                  <code>{ENV[k]}</code>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
