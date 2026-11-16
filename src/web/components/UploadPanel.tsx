import { useRef, useState } from 'react';
import type { UploadResponse } from '../../shared/types.ts';

interface Props {
  onUploaded: (r: UploadResponse) => void;
  authHeaders: Record<string, string>;
}

/** Client-side checks are advisory only; the gateway re-checks everything. */
export function UploadPanel({ onUploaded, authHeaders }: Props) {
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const send = async (files: FileList | File[]) => {
    const list = Array.from(files);
    if (list.length === 0 || busy) return;
    setBusy(true);
    setError(null);
    try {
      const fd = new FormData();
      for (const f of list.slice(0, 20)) fd.append('file', f, f.name);
      const res = await fetch('/api/upload', { method: 'POST', body: fd, headers: authHeaders });
      if (!res.ok) {
        const body = (await res.json().catch(() => ({}))) as { error?: string };
        throw new Error(body.error ?? `上传失败 (${res.status})`);
      }
      onUploaded((await res.json()) as UploadResponse);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
      if (inputRef.current) inputRef.current.value = '';
    }
  };

  return (
    <div className="upload">
      <h2>提交文件</h2>
      <p className="hint">
        扩展名不参与判断。网关按字节内容识别格式，压缩包在展开前估算，图片一律重编码。
      </p>
      <div
        className={dragging ? 'dropzone dragging' : 'dropzone'}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          void send(e.dataTransfer.files);
        }}
        onClick={() => inputRef.current?.click()}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') inputRef.current?.click();
        }}
      >
        <span className="dropzone-title">{busy ? '安检中…' : '拖入文件，或点击选择'}</span>
        <span className="dropzone-sub">单次最多 20 个文件</span>
        <input
          ref={inputRef}
          type="file"
          multiple
          hidden
          onChange={(e) => {
            if (e.target.files) void send(e.target.files);
          }}
        />
      </div>
      {error && (
        <div className="alert" role="alert">
          {error}
        </div>
      )}
    </div>
  );
}
