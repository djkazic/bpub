(() => {
  const SAFE_IMG_EXTS = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
  const PAGE_SIZE = 24;
  const MAX_TEXT_PREVIEW_BYTES = 32 * 1024;

  const state = {
    offset: 0,
    total: 0,
    explorerBaseUrl: '',
    ordersEnabled: false,
    maxUploadBytes: 190 * 1024,
    activeOrderId: null,
    orderPollTimer: null,
    modalTxid: null,
  };

  const $ = (id) => document.getElementById(id);

  function fmtBytes(n) {
    if (n == null) return 'unknown';
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
    return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
  }

  function isSafeImage(name) {
    if (typeof name !== 'string') return false;
    const lower = name.toLowerCase();
    return SAFE_IMG_EXTS.some((ext) => lower.endsWith(ext));
  }

  function isTextPreviewable(item) {
    const mime = (item.mime || '').toLowerCase();
    const fname = (item.stored_filename || '').toLowerCase();
    return fname.endsWith('.txt') || mime.startsWith('text/') || mime === 'application/json';
  }

  function mediaUrl(storedFilename) {
    return '/media/' + encodeURIComponent(storedFilename);
  }

  async function copyText(text, btn) {
    try {
      await navigator.clipboard.writeText(text);
      if (btn) {
        const prev = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = prev; }, 1400);
      }
    } catch (_) {
      // Fallback for non-HTTPS local contexts
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
  }

  function makeCopyButton(label, text) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-secondary btn-sm';
    btn.textContent = label;
    btn.addEventListener('click', () => copyText(text, btn));
    return btn;
  }

  function downloadBase64Psbt(filename, psbtB64) {
    const raw = atob(psbtB64);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    const blob = new Blob([bytes], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  // ------------------------------------------------------------------
  // Tabs
  // ------------------------------------------------------------------

  function showTab(tab) {
    $('view-gallery').classList.toggle('hidden', tab !== 'gallery');
    $('view-inscribe').classList.toggle('hidden', tab !== 'inscribe');
    $('view-embed').classList.toggle('hidden', tab !== 'embed');
    $('tab-gallery').classList.toggle('active', tab === 'gallery');
    $('tab-inscribe').classList.toggle('active', tab === 'inscribe');
    $('tab-embed').classList.toggle('active', tab === 'embed');
  }

  $('tab-gallery').addEventListener('click', () => showTab('gallery'));
  $('tab-inscribe').addEventListener('click', () => showTab('inscribe'));
  $('tab-embed').addEventListener('click', () => showTab('embed'));

  // ------------------------------------------------------------------
  // Stats & Gallery
  // ------------------------------------------------------------------

  async function loadStats() {
    try {
      const res = await fetch('/api/stats');
      if (!res.ok) return;
      const st = await res.json();
      state.explorerBaseUrl = st.explorer_base_url || '';
      state.ordersEnabled = Boolean(st.orders_enabled);
      state.maxUploadBytes = st.max_upload_bytes || state.maxUploadBytes;

      $('order-disabled-banner').classList.toggle('hidden', state.ordersEnabled);
      $('order-studio').classList.toggle('hidden', !state.ordersEnabled);

      const height = st.indexed_height != null ? `Block #${st.indexed_height}` : 'Not synced yet';
      $('stats-bar').textContent =
        `${st.total_items} indexed · ${fmtBytes(st.total_bytes)} on-chain · ` +
        `${st.v5_owned_count} verified v5 owners · ${height}`;
    } catch (_) {
      $('stats-bar').textContent = 'Stats unavailable';
    }
  }

  async function loadGallery() {
    const params = new URLSearchParams({
      limit: String(PAGE_SIZE),
      offset: String(state.offset),
    });
    const q = $('search-input').value.trim();
    const mime = $('mime-filter').value;
    const ver = $('version-filter').value;
    if (q) params.set('q', q);
    if (mime) params.set('mime', mime);
    if (ver) params.set('version', ver);

    const grid = $('grid');
    grid.textContent = 'Loading…';

    try {
      const res = await fetch('/api/items?' + params.toString());
      if (!res.ok) {
        grid.textContent = `Error loading items (${res.status})`;
        return;
      }
      const data = await res.json();
      state.total = data.total || 0;
      renderGrid(data.items || []);
      renderPager();
    } catch (_) {
      grid.textContent = 'Failed to fetch gallery items.';
    }
  }

  function renderGrid(items) {
    const grid = $('grid');
    grid.textContent = '';

    if (!items.length) {
      const empty = document.createElement('p');
      empty.className = 'info';
      empty.textContent = 'No BPUB items match your query.';
      grid.appendChild(empty);
      return;
    }

    items.forEach((item) => {
      if (typeof item.stored_filename !== 'string' || !item.stored_filename) return;
      if (item.stored_filename.includes('/') || item.stored_filename.includes('..')) return;

      const card = document.createElement('div');
      card.className = 'card';
      card.addEventListener('click', () => {
        window.location.hash = `tx=${encodeURIComponent(item.txid)}`;
      });

      const mediaBox = document.createElement('div');
      mediaBox.className = 'card-media';
      if (isSafeImage(item.stored_filename)) {
        const img = document.createElement('img');
        img.src = mediaUrl(item.stored_filename);
        img.alt = item.filename || item.txid;
        img.loading = 'lazy';
        mediaBox.appendChild(img);
      } else {
        const ph = document.createElement('div');
        ph.className = 'file-placeholder';
        ph.textContent = item.mime || 'application/octet-stream';
        mediaBox.appendChild(ph);
      }

      const meta = document.createElement('div');
      meta.className = 'meta';

      const name = document.createElement('div');
      name.className = 'filename';
      name.textContent = item.filename || '(unnamed)';

      const info = document.createElement('div');
      info.className = 'info';
      const suffix = item.script_suffix ? ` · ${item.script_suffix}` : '';
      info.textContent = `${fmtBytes(item.size)} · ${item.mime || 'binary'} · #${item.block_height}${suffix}`;

      const tx = document.createElement('div');
      tx.className = 'mono info';
      tx.textContent = item.txid.slice(0, 20) + '…';

      meta.appendChild(name);
      meta.appendChild(info);
      meta.appendChild(tx);

      if (item.ownership) {
        const addr = item.ownership.current_owner_p2wpkh || item.ownership.current_owner_p2wsh;
        if (addr) {
          const own = document.createElement('div');
          own.className = 'mono owner-line';
          own.textContent = 'Owner: ' + addr.slice(0, 22) + '…';
          meta.appendChild(own);
        }
      }

      card.appendChild(mediaBox);
      card.appendChild(meta);
      grid.appendChild(card);
    });
  }

  function renderPager() {
    const pager = $('pager');
    if (state.total <= PAGE_SIZE) {
      pager.classList.add('hidden');
      return;
    }
    pager.classList.remove('hidden');
    const page = Math.floor(state.offset / PAGE_SIZE) + 1;
    const pages = Math.ceil(state.total / PAGE_SIZE);
    $('page-info').textContent = `Page ${page} of ${pages} (${state.total} total)`;
    $('prev-page').disabled = state.offset === 0;
    $('next-page').disabled = state.offset + PAGE_SIZE >= state.total;
  }

  $('search-btn').addEventListener('click', () => { state.offset = 0; loadGallery(); });
  $('search-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { state.offset = 0; loadGallery(); }
  });
  $('mime-filter').addEventListener('change', () => { state.offset = 0; loadGallery(); });
  $('version-filter').addEventListener('change', () => { state.offset = 0; loadGallery(); });
  $('prev-page').addEventListener('click', () => {
    state.offset = Math.max(0, state.offset - PAGE_SIZE);
    loadGallery();
  });
  $('next-page').addEventListener('click', () => {
    state.offset += PAGE_SIZE;
    loadGallery();
  });

  // ------------------------------------------------------------------
  // Detail Modal + Shareable Deep Links + Safe Text Preview
  // ------------------------------------------------------------------

  function closeModal() {
    $('modal-backdrop').classList.add('hidden');
    state.modalTxid = null;
    if (window.location.hash.startsWith('#tx=') || window.location.hash.startsWith('#id=')) {
      history.replaceState(null, '', window.location.pathname + window.location.search);
    }
  }

  async function openDetail(endpointPath) {
    const backdrop = $('modal-backdrop');
    const body = $('modal-body');
    $('modal-title').textContent = 'Loading…';
    body.textContent = '';
    backdrop.classList.remove('hidden');

    try {
      const res = await fetch(endpointPath);
      if (!res.ok) {
        body.textContent = 'Item not found.';
        return;
      }
      const item = await res.json();
      state.modalTxid = item.txid;
      $('modal-title').textContent = item.filename || item.txid;

      const media = document.createElement('div');
      media.className = 'modal-media';
      const url = mediaUrl(item.stored_filename);
      if (isSafeImage(item.stored_filename)) {
        const img = document.createElement('img');
        img.src = url;
        img.alt = item.filename || item.txid;
        media.appendChild(img);
        body.appendChild(media);
      } else if (isTextPreviewable(item) && (item.size || 0) <= MAX_TEXT_PREVIEW_BYTES) {
        const pre = document.createElement('pre');
        pre.className = 'text-preview';
        pre.textContent = 'Loading text preview…';
        body.appendChild(pre);
        fetch(url)
          .then((r) => (r.ok ? r.text() : ''))
          .then((txt) => {
            pre.textContent = txt.slice(0, MAX_TEXT_PREVIEW_BYTES) || '(empty)';
          })
          .catch(() => { pre.textContent = 'Preview unavailable.'; });
      }

      const dl = document.createElement('dl');
      dl.className = 'kv';

      const addRow = (k, v, href, copyVal) => {
        const dt = document.createElement('dt');
        dt.textContent = k;
        const dd = document.createElement('dd');
        dd.className = 'mono kv-val';
        if (href) {
          const a = document.createElement('a');
          a.href = href;
          a.target = '_blank';
          a.rel = 'noopener noreferrer';
          a.textContent = v;
          dd.appendChild(a);
        } else {
          const span = document.createElement('span');
          span.textContent = v;
          dd.appendChild(span);
        }
        if (copyVal) {
          dd.appendChild(makeCopyButton('Copy', copyVal));
        }
        dl.appendChild(dt);
        dl.appendChild(dd);
      };

      const txHref = state.explorerBaseUrl ? `${state.explorerBaseUrl}/tx/${item.txid}` : null;
      addRow('Reveal TXID', item.txid, txHref, item.txid);
      addRow('Block Height', String(item.block_height));
      addRow('Size / MIME', `${fmtBytes(item.size)} (${item.mime || 'unknown'})`);
      addRow('Format', `BPUB v${item.bpub_version || '?'} (${item.script_suffix || 'unknown'})`);
      if (item.bpub_id) addRow('BPUB v5 ID', item.bpub_id, null, item.bpub_id);
      addRow('File', 'Open / Download', url);

      if (item.ownership) {
        const addr = item.ownership.current_owner_p2wpkh || item.ownership.current_owner_p2wsh || '(unrevealed)';
        addRow('Current Owner', addr, null, addr.startsWith('bc1') ? addr : null);
        if (item.ownership.current_outpoint) {
          addRow('Owner UTXO', item.ownership.current_outpoint);
        }
      }
      body.appendChild(dl);

      if (Array.isArray(item.ownership_history) && item.ownership_history.length > 0) {
        const h = document.createElement('h3');
        h.className = 'detail-subhead';
        h.textContent = `Ownership History (${item.ownership_history.length})`;
        body.appendChild(h);

        item.ownership_history.forEach((ev) => {
          const p = document.createElement('div');
          p.className = 'mono info hist-line';
          const to = ev.new_owner_p2wpkh || ev.new_owner_p2wsh || 'unknown';
          p.textContent = `Block #${ev.block_height} · tx ${ev.txid.slice(0, 16)}… · signer ${ev.signer_p2wpkh || '?'} → ${to}`;
          body.appendChild(p);
        });
      }
    } catch (_) {
      body.textContent = 'Error loading item.';
    }
  }

  function handleHashRoute() {
    const h = window.location.hash || '';
    if (h.startsWith('#tx=')) {
      const txid = decodeURIComponent(h.slice(4)).trim();
      if (/^[0-9a-fA-F]{64}$/.test(txid)) {
        showTab('gallery');
        openDetail('/api/items/' + encodeURIComponent(txid));
      }
    } else if (h.startsWith('#id=')) {
      const bid = decodeURIComponent(h.slice(4)).trim();
      if (/^[0-9a-fA-F]{64}$/.test(bid)) {
        showTab('gallery');
        openDetail('/api/id/' + encodeURIComponent(bid));
      }
    } else if (h.startsWith('#order=')) {
      const oid = decodeURIComponent(h.slice(7)).trim();
      if (/^[0-9a-f]{32}$/.test(oid)) {
        showTab('inscribe');
        startOrderPolling(oid);
      }
    }
  }

  window.addEventListener('hashchange', handleHashRoute);
  $('modal-close').addEventListener('click', closeModal);
  $('modal-copy-link').addEventListener('click', () => {
    if (!state.modalTxid) return;
    const shareUrl = `${window.location.origin}${window.location.pathname}#tx=${state.modalTxid}`;
    copyText(shareUrl, $('modal-copy-link'));
  });
  $('modal-backdrop').addEventListener('click', (e) => {
    if (e.target === $('modal-backdrop')) closeModal();
  });

  // ------------------------------------------------------------------
  // Instant Inscribe (Custodial LND -> padv3)
  // ------------------------------------------------------------------

  async function updateOrderQuote() {
    const file = $('order-file').files[0];
    const box = $('order-quote-out');
    if (!file || !state.ordersEnabled) {
      box.classList.add('hidden');
      return;
    }
    if (file.size > state.maxUploadBytes) {
      box.classList.remove('hidden');
      box.className = 'output-box msg-err';
      box.textContent = `File (${fmtBytes(file.size)}) exceeds max upload size (${fmtBytes(state.maxUploadBytes)}).`;
      return;
    }
    const fd = new FormData();
    fd.append('file', file);
    fd.append('filename', $('order-filename').value.trim());
    fd.append('mime', $('order-mime').value.trim() || 'application/octet-stream');
    fd.append('compress', $('order-compress').value);

    try {
      const res = await fetch('/api/orders/quote', { method: 'POST', body: fd });
      const data = await res.json();
      box.classList.remove('hidden');
      if (!res.ok) {
        box.className = 'output-box msg-err';
        box.textContent = data.detail || 'Quote failed';
        return;
      }
      box.className = 'output-box';
      const confNote = data.needs_funding_conf
        ? ' · large reveal (waits for 1 funding confirmation)'
        : '';
      box.textContent =
        `Lightning price: ${data.ln_amount_sats} sats · ` +
        `${data.data_outputs_count} padv3 outputs (${fmtBytes(data.stream_bytes)} encoded${confNote})`;
    } catch (_) {
      box.classList.remove('hidden');
      box.className = 'output-box msg-err';
      box.textContent = 'Failed to fetch quote.';
    }
  }

  $('order-file').addEventListener('change', () => {
    const file = $('order-file').files[0];
    if (file) {
      $('order-filename').value = file.name.slice(0, 120);
      if (file.type) $('order-mime').value = file.type;
    }
    updateOrderQuote();
  });
  $('order-compress').addEventListener('change', updateOrderQuote);

  function renderOrderStatus(order) {
    const panel = $('order-status-panel');
    const body = $('order-status-body');
    panel.classList.remove('hidden');
    body.textContent = '';

    const statusLine = document.createElement('div');
    statusLine.className = 'order-status-pill';
    statusLine.textContent = `Status: ${order.status} · Order ${order.order_id.slice(0, 12)}… · ${order.ln_amount_sats} LN sats`;
    body.appendChild(statusLine);

    if (order.payment_request && order.status === 'awaiting_payment') {
      const p = document.createElement('p');
      p.className = 'info';
      p.textContent = 'Pay this Lightning invoice to begin your on-chain padv3 inscription:';
      body.appendChild(p);

      const ta = document.createElement('textarea');
      ta.readOnly = true;
      ta.rows = 3;
      ta.className = 'mono invoice-box';
      ta.value = order.payment_request;
      body.appendChild(ta);

      const row = document.createElement('div');
      row.className = 'actions-row';
      row.appendChild(makeCopyButton('Copy Invoice', order.payment_request));
      body.appendChild(row);
    }

    if (order.status === 'awaiting_liquidity') {
      const p = document.createElement('p');
      p.className = 'info';
      p.textContent =
        'Lightning payment settled! Waiting for hot-wallet UTXO confirmation before broadcasting your inscription automatically…';
      body.appendChild(p);
    }

    if (order.status === 'awaiting_funding_conf') {
      const p = document.createElement('p');
      p.className = 'info';
      p.textContent =
        'Funding transaction broadcast! Because this large inscription exceeds the 101k vB ' +
        'unconfirmed ancestor limit, the signed reveal will broadcast automatically after 1 confirmation.';
      body.appendChild(p);
    }

    const dl = document.createElement('dl');
    dl.className = 'kv';
    const addKv = (k, v, href) => {
      const dt = document.createElement('dt');
      dt.textContent = k;
      const dd = document.createElement('dd');
      dd.className = 'mono kv-val';
      if (href) {
        const a = document.createElement('a');
        a.href = href;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.textContent = v;
        dd.appendChild(a);
      } else {
        dd.textContent = v;
      }
      dd.appendChild(makeCopyButton('Copy', v));
      dl.appendChild(dt);
      dl.appendChild(dd);
    };
    if (order.bpub_id) addKv('BPUB v5 ID', order.bpub_id, null);
    if (order.funding_txid) addKv('Funding TXID', order.funding_txid, order.funding_explorer_url);
    if (order.reveal_txid) addKv('Reveal TXID', order.reveal_txid, order.reveal_explorer_url);
    body.appendChild(dl);

    if (order.error_message) {
      const err = document.createElement('p');
      err.className = 'msg-err';
      err.textContent = order.error_message;
      body.appendChild(err);
    }
  }

  function stopOrderPolling() {
    if (state.orderPollTimer) {
      clearInterval(state.orderPollTimer);
      state.orderPollTimer = null;
    }
  }

  async function pollOrderOnce(orderId) {
    try {
      const res = await fetch('/api/orders/' + encodeURIComponent(orderId));
      if (!res.ok) return;
      const order = await res.json();
      renderOrderStatus(order);
      if (order.status === 'completed' || order.status === 'expired' || order.status === 'failed') {
        stopOrderPolling();
      }
    } catch (_) {
      // transient network error; retry on next tick
    }
  }

  function startOrderPolling(orderId) {
    stopOrderPolling();
    state.activeOrderId = orderId;
    pollOrderOnce(orderId);
    state.orderPollTimer = setInterval(() => pollOrderOnce(orderId), 3000);
  }

  $('btn-create-order').addEventListener('click', async () => {
    const file = $('order-file').files[0];
    const qbox = $('order-quote-out');
    if (!file) {
      qbox.classList.remove('hidden');
      qbox.className = 'output-box msg-err';
      qbox.textContent = 'Select a file first.';
      return;
    }
    const fd = new FormData();
    fd.append('file', file);
    fd.append('filename', $('order-filename').value.trim());
    fd.append('mime', $('order-mime').value.trim() || 'application/octet-stream');
    fd.append('compress', $('order-compress').value);

    const btn = $('btn-create-order');
    btn.disabled = true;
    try {
      const res = await fetch('/api/orders', { method: 'POST', body: fd });
      const data = await res.json();
      if (!res.ok) {
        qbox.classList.remove('hidden');
        qbox.className = 'output-box msg-err';
        qbox.textContent = data.detail || 'Order creation failed';
        return;
      }
      renderOrderStatus(data);
      history.replaceState(null, '', `#order=${data.order_id}`);
      startOrderPolling(data.order_id);
    } catch (_) {
      qbox.classList.remove('hidden');
      qbox.className = 'output-box msg-err';
      qbox.textContent = 'Request failed.';
    } finally {
      btn.disabled = false;
    }
  });

  // ------------------------------------------------------------------
  // Self-Custody padv3 PSBT Studio
  // ------------------------------------------------------------------

  async function updateEstimate() {
    const file = $('embed-file').files[0];
    const box = $('estimate-out');
    if (!file) {
      box.classList.add('hidden');
      return;
    }
    if (file.size > state.maxUploadBytes) {
      box.classList.remove('hidden');
      box.textContent = `File (${fmtBytes(file.size)}) exceeds the ${fmtBytes(state.maxUploadBytes)} single-tx padv3 limit.`;
      box.className = 'output-box msg-err';
      return;
    }

    try {
      const res = await fetch('/api/embed/estimate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          size_bytes: file.size,
          feerate: parseInt($('embed-feerate').value, 10) || 1,
          reveal_feerate: parseInt($('embed-reveal-feerate').value, 10) || 1,
          owner_value: parseInt($('embed-owner-value').value, 10) || 10000,
          filename: $('embed-filename').value.trim(),
          mime: $('embed-mime').value.trim() || 'application/octet-stream',
        }),
      });
      const data = await res.json();
      box.classList.remove('hidden');
      if (!res.ok) {
        box.className = 'output-box msg-err';
        box.textContent = data.detail || 'Estimate failed';
        return;
      }
      box.className = 'output-box';
      box.textContent =
        `padv3 estimate: ${data.data_outputs} data outputs × ${data.per_output_sats} sats ` +
        `+ ${data.owner_output_sats} owner + ~${data.funding_fee_sats} funding fee ` +
        `(reveal fee ~${data.reveal_fee_sats} sats) → min funding UTXO: ${data.min_funding_utxo_sats} sats`;
    } catch (_) {
      box.classList.remove('hidden');
      box.className = 'output-box msg-err';
      box.textContent = 'Failed to estimate cost.';
    }
  }

  $('embed-file').addEventListener('change', () => {
    const file = $('embed-file').files[0];
    if (file) {
      $('embed-filename').value = file.name.slice(0, 120);
      if (file.type) $('embed-mime').value = file.type;
    }
    updateEstimate();
  });
  $('embed-feerate').addEventListener('change', updateEstimate);
  $('embed-reveal-feerate').addEventListener('change', updateEstimate);
  $('embed-owner-value').addEventListener('change', updateEstimate);

  $('btn-lookup-utxo').addEventListener('click', async () => {
    const raw = $('fund-utxo').value.trim();
    const parts = raw.split(':');
    const out = $('fund-out');
    if (parts.length !== 2) {
      out.classList.remove('hidden');
      out.className = 'output-box msg-err';
      out.textContent = 'Enter UTXO as TXID:VOUT first.';
      return;
    }
    try {
      const res = await fetch(`/api/utxo/${encodeURIComponent(parts[0])}/${encodeURIComponent(parts[1])}`);
      const data = await res.json();
      if (!res.ok) {
        out.classList.remove('hidden');
        out.className = 'output-box msg-err';
        out.textContent = data.detail || 'UTXO lookup failed';
        return;
      }
      if (data.value != null) $('fund-value').value = String(data.value);
      if (data.address) $('fund-prev-addr').value = data.address;
      out.classList.remove('hidden');
      out.className = 'output-box msg-ok';
      out.textContent = `Loaded UTXO: ${data.value} sats (${data.address || 'unknown addr'})`;
    } catch (_) {
      out.classList.remove('hidden');
      out.className = 'output-box msg-err';
      out.textContent = 'Explorer lookup failed.';
    }
  });

  function renderPsbtBox(box, summaryText, psbtB64, downloadName) {
    box.classList.remove('hidden');
    box.className = 'output-box';
    box.textContent = '';
    const p = document.createElement('div');
    p.className = 'msg-ok';
    p.textContent = summaryText;
    const ta = document.createElement('textarea');
    ta.readOnly = true;
    ta.value = psbtB64;
    const actions = document.createElement('div');
    actions.className = 'actions-row';
    actions.appendChild(makeCopyButton('Copy PSBT', psbtB64));
    const dlBtn = document.createElement('button');
    dlBtn.type = 'button';
    dlBtn.className = 'btn btn-secondary btn-sm';
    dlBtn.textContent = `Download ${downloadName}`;
    dlBtn.addEventListener('click', () => downloadBase64Psbt(downloadName, psbtB64));
    actions.appendChild(dlBtn);
    box.appendChild(p);
    box.appendChild(ta);
    box.appendChild(actions);
  }

  $('btn-build-fund').addEventListener('click', async () => {
    const file = $('embed-file').files[0];
    const out = $('fund-out');
    if (!file) {
      out.classList.remove('hidden');
      out.className = 'output-box msg-err';
      out.textContent = 'Select a file in Step 1 first.';
      return;
    }
    const fd = new FormData();
    fd.append('file', file);
    fd.append('filename', $('embed-filename').value.trim());
    fd.append('mime', $('embed-mime').value.trim() || 'application/octet-stream');
    fd.append('compress', $('embed-compress').value);
    fd.append('control_pubkey', $('fund-control-pk').value.trim());
    fd.append('owner_address', $('fund-owner-addr').value.trim());
    fd.append('owner_value', $('embed-owner-value').value.trim() || '10000');
    fd.append('utxo', $('fund-utxo').value.trim());
    fd.append('value', $('fund-value').value.trim());
    fd.append('prev_address', $('fund-prev-addr').value.trim());
    fd.append('change', $('fund-change-addr').value.trim());
    fd.append('feerate', $('embed-feerate').value.trim() || '1');
    fd.append('reveal_feerate', $('embed-reveal-feerate').value.trim() || '1');

    try {
      const res = await fetch('/api/embed/fund-psbt', { method: 'POST', body: fd });
      const data = await res.json();
      if (!res.ok) {
        out.classList.remove('hidden');
        out.className = 'output-box msg-err';
        out.textContent = data.detail || 'Failed to build funding PSBT';
        return;
      }
      renderPsbtBox(
        out,
        `Funding PSBT ready (txid ${data.funding_txid}, ${data.data_outputs_count} × ${data.per_output_sats} sats, bpub_id ${data.bpub_id})`,
        data.funding_psbt,
        'funding.psbt',
      );
      $('reveal-utxos').value = (data.bpub_utxos || []).join('\n');
    } catch (_) {
      out.classList.remove('hidden');
      out.className = 'output-box msg-err';
      out.textContent = 'Request failed.';
    }
  });

  $('btn-build-reveal').addEventListener('click', async () => {
    const file = $('embed-file').files[0];
    const out = $('reveal-out');
    if (!file) {
      out.classList.remove('hidden');
      out.className = 'output-box msg-err';
      out.textContent = 'Select a file in Step 1 first.';
      return;
    }
    const fd = new FormData();
    fd.append('file', file);
    fd.append('filename', $('embed-filename').value.trim());
    fd.append('mime', $('embed-mime').value.trim() || 'application/octet-stream');
    fd.append('compress', $('embed-compress').value);
    fd.append('control_pubkey', $('fund-control-pk').value.trim());
    fd.append('bpub_utxos', $('reveal-utxos').value.trim());
    fd.append('change', $('fund-change-addr').value.trim());
    fd.append('feerate', $('embed-reveal-feerate').value.trim() || '1');

    try {
      const res = await fetch('/api/embed/reveal-psbt', { method: 'POST', body: fd });
      const data = await res.json();
      if (!res.ok) {
        out.classList.remove('hidden');
        out.className = 'output-box msg-err';
        out.textContent = data.detail || 'Failed to build reveal PSBT';
        return;
      }
      renderPsbtBox(
        out,
        `Reveal PSBT ready (${data.inputs} padv3 inputs, fee ~${data.fee_sats} sats, change ${data.change_value_sats} sats)`,
        data.reveal_psbt,
        'reveal.psbt',
      );
    } catch (_) {
      out.classList.remove('hidden');
      out.className = 'output-box msg-err';
      out.textContent = 'Request failed.';
    }
  });

  $('btn-broadcast').addEventListener('click', async () => {
    const hex = $('bcast-hex').value.trim();
    const out = $('bcast-out');
    if (!hex) {
      out.classList.remove('hidden');
      out.className = 'output-box msg-err';
      out.textContent = 'Paste signed raw transaction hex first.';
      return;
    }
    try {
      const res = await fetch('/api/tx/broadcast', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_hex: hex }),
      });
      const data = await res.json();
      out.classList.remove('hidden');
      if (!res.ok) {
        out.className = 'output-box msg-err';
        out.textContent = data.detail || 'Broadcast failed';
        return;
      }
      out.className = 'output-box msg-ok';
      out.textContent = '';
      out.appendChild(document.createTextNode('Broadcast accepted! TXID: '));
      if (data.explorer_url) {
        const a = document.createElement('a');
        a.href = data.explorer_url;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.textContent = data.txid;
        out.appendChild(a);
      } else {
        out.appendChild(document.createTextNode(data.txid));
      }
      out.appendChild(document.createTextNode(' '));
      out.appendChild(makeCopyButton('Copy TXID', data.txid));
    } catch (_) {
      out.classList.remove('hidden');
      out.className = 'output-box msg-err';
      out.textContent = 'Broadcast request failed.';
    }
  });

  // Initial load
  loadStats().then(() => {
    loadGallery();
    handleHashRoute();
  });
})();
