import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AgGridReact } from 'ag-grid-react';

const HIGH_SIGNAL_CORE = new Set([
  'Anthropic API Key', 'OpenAI API Key', 'OpenAI Project API Key', 'OpenAI Live API Key',
  'OpenRouter API Key', 'Together AI API Key', 'Groq API Key', 'Hugging Face API Key',
  'Google API Key', 'AWS Access Key ID', 'AWS Secret Access Key', 'Private Key', 'SSH Key',
  'PostgreSQL Connection String', 'MySQL Connection String', 'MongoDB Connection String',
  'LLM Provider ENV Key', 'Data Provider ENV Key', 'API Key', 'Auth Key', 'Secret Key',
  'Generic Token', 'SMTP Credentials', 'ENV Variable Credential', 'wp-config.php Credentials',
  'RapidAPI Header Key', 'X-API-Key Header', 'Bearer Token', 'NewsAPI Key', 'RapidAPI Key',
]);

function isHighSignal(type) {
  if (!type) return false;
  return HIGH_SIGNAL_CORE.has(type)
    || type.endsWith(' API Key')
    || type.endsWith(' API Token');
}

const FILTER_DEBOUNCE_MS = 400;
const AUTO_REFRESH_MS = 30000;

function CommitLink({ value, data }) {
  if (!data?.commit_url) return value;
  return (
    <a href={data.commit_url} target="_blank" rel="noopener noreferrer">
      {String(value).slice(0, 7)}
    </a>
  );
}

function TypeCell({ value }) {
  const high = isHighSignal(value);
  return <span className={high ? 'badge-high' : ''}>{value}</span>;
}

function SecretCell({ value }) {
  const text = String(value ?? '');
  const preview = text.length > 100 ? `${text.slice(0, 97)}…` : text;
  return <span className="secret-cell" title={text}>{preview}</span>;
}

async function fetchJson(url) {
  const res = await fetch(url);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `Request failed: ${res.status}`);
  return data;
}

function formatTimestamp(value) {
  if (!value) return '—';
  return String(value).replace('T', ' ').slice(0, 19);
}

export default function App() {
  const gridRef = useRef(null);
  const [summary, setSummary] = useState(null);
  const [types, setTypes] = useState([]);
  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [repoFilter, setRepoFilter] = useState('');
  const [highOnly, setHighOnly] = useState(false);

  const columnDefs = useMemo(() => [
    {
      field: 'detected_at',
      headerName: 'When',
      filter: 'agTextColumnFilter',
      sort: 'desc',
      width: 170,
      valueFormatter: (p) => formatTimestamp(p.value),
    },
    {
      field: 'secret_type',
      headerName: 'Type',
      filter: 'agTextColumnFilter',
      width: 180,
      cellRenderer: TypeCell,
    },
    {
      field: 'repo',
      headerName: 'Repo',
      filter: 'agTextColumnFilter',
      flex: 1,
      minWidth: 180,
    },
    {
      field: 'filename',
      headerName: 'File',
      filter: 'agTextColumnFilter',
      flex: 1,
      minWidth: 180,
    },
    {
      field: 'secret',
      headerName: 'Secret',
      filter: 'agTextColumnFilter',
      flex: 2,
      minWidth: 260,
      cellRenderer: SecretCell,
    },
    {
      field: 'commit_sha',
      headerName: 'Commit',
      filter: 'agTextColumnFilter',
      width: 110,
      cellRenderer: CommitLink,
    },
  ], []);

  const defaultColDef = useMemo(() => ({
    sortable: true,
    filter: true,
    resizable: true,
    floatingFilter: false,
  }), []);

  const loadSummary = useCallback(async () => {
    const data = await fetchJson('/api/summary');
    setSummary(data);
    return data;
  }, []);

  const loadTypes = useCallback(async () => {
    const data = await fetchJson('/api/types');
    setTypes(data.types || []);
    return data;
  }, []);

  const loadFindings = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const params = new URLSearchParams({
        q: search.trim(),
        type: typeFilter,
        repo: repoFilter.trim(),
        high_signal: highOnly ? '1' : '0',
        limit: '5000',
        offset: '0',
        sort: 'detected_at',
        order: 'desc',
      });
      const data = await fetchJson(`/api/findings?${params}`);
      setRows(data.items || []);
      setTotal(data.total || 0);
      setLastUpdated(new Date());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [search, typeFilter, repoFilter, highOnly]);

  const rebuild = useCallback(async () => {
    await Promise.all([loadSummary(), loadTypes(), loadFindings()]);
  }, [loadSummary, loadTypes, loadFindings]);

  useEffect(() => {
    loadSummary().catch((err) => setError(err.message));
    loadTypes().catch((err) => setError(err.message));
  }, [loadSummary, loadTypes]);

  useEffect(() => {
    const timer = setTimeout(() => {
      loadFindings().catch((err) => setError(err.message));
    }, FILTER_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [search, typeFilter, repoFilter, highOnly, loadFindings]);

  useEffect(() => {
    const timer = setInterval(() => {
      loadSummary().catch(() => {});
      loadTypes().catch(() => {});
      loadFindings().catch(() => {});
    }, AUTO_REFRESH_MS);
    return () => clearInterval(timer);
  }, [loadSummary, loadTypes, loadFindings]);

  const exportCsv = () => {
    gridRef.current?.api?.exportDataAsCsv({ fileName: 'gitscout-findings.csv' });
  };

  const clearGridFilters = () => {
    gridRef.current?.api?.setFilterModel(null);
  };

  const loadedHint = rows.length < total
    ? `${rows.length} of ${total} (server cap 5,000)`
    : String(rows.length);

  return (
    <div className="app">
      <header>
        <h1>GitScout Findings</h1>
        <p>React grid — filter, search, sort, export</p>
      </header>

      {error && <div className="error">{error}</div>}

      <div className="cards">
        <div className="card"><div className="label">Total</div><div className="value">{summary?.total ?? '—'}</div></div>
        <div className="card"><div className="label">High-signal</div><div className="value">{summary?.high_signal ?? '—'}</div></div>
        <div className="card"><div className="label">Loaded rows</div><div className="value">{loading ? '…' : loadedHint}</div></div>
        <div className="card"><div className="label">Matching query</div><div className="value">{loading ? '…' : total}</div></div>
      </div>

      <div className="toolbar">
        <input
          type="search"
          placeholder="Server search: secret, file, repo, commit..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ minWidth: 280, flex: 1 }}
        />
        <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
          <option value="">All types</option>
          {types.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <input
          type="text"
          placeholder="Repo filter"
          value={repoFilter}
          onChange={(e) => setRepoFilter(e.target.value)}
        />
        <label>
          <input type="checkbox" checked={highOnly} onChange={(e) => setHighOnly(e.target.checked)} />
          High-signal only
        </label>
        <button type="button" onClick={rebuild} disabled={loading}>
          {loading ? 'Loading…' : 'Rebuild'}
        </button>
        <button type="button" onClick={clearGridFilters}>Clear grid filters</button>
        <button type="button" onClick={exportCsv}>Export CSV</button>
      </div>

      <div className={`grid-wrap${loading ? ' grid-wrap--loading' : ''}`}>
        {loading && <div className="grid-overlay" aria-live="polite">Updating findings…</div>}
        <div className="ag-theme-quartz-dark gitscout-grid grid-inner">
          <AgGridReact
            ref={gridRef}
            rowData={rows}
            columnDefs={columnDefs}
            defaultColDef={defaultColDef}
            animateRows={false}
            pagination
            paginationPageSize={50}
            paginationPageSizeSelector={[25, 50, 100, 250]}
            suppressCellFocus
            loading={loading}
            overlayNoRowsTemplate="No findings match the current filters."
          />
        </div>
      </div>

      <div className="meta">
        Toolbar filters query the server (auto-refresh every 30s).
        Column filters apply to loaded rows only.
        {lastUpdated && (
          <> Last grid update: {lastUpdated.toLocaleTimeString()}.</>
        )}
        {summary?.last_poll?.at && (
          <> Last scanner poll: {formatTimestamp(summary.last_poll.at)}.</>
        )}
      </div>
    </div>
  );
}