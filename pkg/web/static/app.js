(() => {
  'use strict';

  // Application State
  const state = {
    overview: null,
    history: [],
    routes: [],
    events: [],
    layerCounts: {},
    config: {},
    unit: 'mbps', // 'mbps' | 'gbps' | 'pps'
    hoverIndex: -1,
    editingRouteId: 0,
    formDirty: false,
    particles: [],
    shields: [],
    radarAngle: 0
  };

  // Global Edge Nodes for Cyber Topology Canvas
  const GLOBAL_NODES = [
    { code: 'SFO', country: 'US', label: 'SFO [US-WEST]', x: 0.11, y: 0.34, domestic: false },
    { code: 'FRA', country: 'DE', label: 'FRA [EU-CENTRAL]', x: 0.27, y: 0.24, domestic: false },
    { code: 'MOW', country: 'RU', label: 'MOW [RU-NET]', x: 0.38, y: 0.18, domestic: false },
    { code: 'PEK', country: 'CN', label: 'PEK [CN-BACKBONE]', x: 0.48, y: 0.28, domestic: false },
    { code: 'TYO', country: 'JP', label: 'TYO [JP-IX]', x: 0.56, y: 0.42, domestic: false },
    { code: 'SIN', country: 'SG', label: 'SIN [SG-TRANSIT]', x: 0.45, y: 0.78, domestic: false },
    { code: 'HAN', country: 'VN', label: 'HAN [VN-NORTH]', x: 0.34, y: 0.56, domestic: true },
    { code: 'SGN', country: 'VN', label: 'SGN [VN-SOUTH]', x: 0.35, y: 0.72, domestic: true }
  ];

  const FW_CORE = { x: 0.66, y: 0.54, label: 'AEGIS-FW CORE' };
  const ORIGIN_CORE = { x: 0.89, y: 0.54, label: 'ORIGIN SERVER' };

  // Utility helpers
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  function showToast(msg, isError = false) {
    const container = $('#toastContainer');
    if (!container) return;
    const el = document.createElement('div');
    el.className = 'toast' + (isError ? ' error' : '');
    el.textContent = msg;
    container.appendChild(el);
    setTimeout(() => el.remove(), 3400);
  }

  function formatBytes(bytes) {
    const n = Number(bytes) || 0;
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1073741824) return (n / 1048576).toFixed(2) + ' MB';
    return (n / 1073741824).toFixed(2) + ' GB';
  }

  function formatDuration(sec) {
    const s = Math.max(0, Number(sec) || 0);
    const hrs = String(Math.floor(s / 3600)).padStart(2, '0');
    const mins = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
    const secs = String(s % 60).padStart(2, '0');
    return `${hrs}:${mins}:${secs}`;
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => {
        showToast(`Copied endpoint: ${text}`);
      });
    } else {
      const inp = document.createElement('input');
      inp.value = text;
      document.body.appendChild(inp);
      inp.select();
      document.execCommand('copy');
      inp.remove();
      showToast(`Copied endpoint: ${text}`);
    }
  }

  // Tab Navigation
  function initTabs() {
    $$('.nav-tab').forEach((btn) => {
      btn.addEventListener('click', () => {
        const target = btn.getAttribute('data-tab');
        $$('.nav-tab').forEach((b) => b.classList.remove('active'));
        $$('.tab-pane').forEach((p) => p.classList.remove('active'));
        btn.classList.add('active');
        const pane = $(`#tab-${target}`);
        if (pane) pane.classList.add('active');
        if (target === 'acl') loadACL();
      });
    });

    const jumpBtn = $('#btnJumpAddRoute');
    if (jumpBtn) {
      jumpBtn.addEventListener('click', () => {
        const epTab = document.querySelector('.nav-tab[data-tab="endpoints"]');
        if (epTab) epTab.click();
        $('#routeNameInput')?.focus();
      });
    }
  }

  // Unit switcher for 180s Oscilloscope
  function initUnitSwitcher() {
    $$('.unit-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        $$('.unit-btn').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        state.unit = btn.getAttribute('data-unit') || 'mbps';
        drawTrafficChart();
      });
    });
  }

  // Bind all ON/OFF toggle switches across Overview & Switchboard tabs
  function initConfigSwitches() {
    $$('input[data-cfg-toggle]').forEach((chk) => {
      chk.addEventListener('change', async () => {
        const key = chk.getAttribute('data-cfg-toggle');
        const val = chk.checked;
        // Sync all switches sharing the same key
        $$(`input[data-cfg-toggle="${key}"]`).forEach((other) => {
          other.checked = val;
        });

        try {
          const res = await fetch('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ [key]: val })
          });
          const data = await res.json();
          if (data.ok) {
            showToast(`[ENGINE] ${key.toUpperCase()} -> ${val ? 'ENABLED (ON)' : 'DISABLED (OFF)'}`);
            fetchOverview();
          } else {
            showToast(data.error || 'Failed to update toggle', true);
          }
        } catch (err) {
          showToast('Network error updating switch', true);
        }
      });
    });

    // Quick Apply bar on Overview tab
    $('#btnQuickApply')?.addEventListener('click', async () => {
      const payload = {
        geoip_allowed_countries: $('#quickAllowedCC')?.value || 'VN',
        geoip_direction: $('#quickGeoDir')?.value || 'both',
        proxy_protocol: $('#quickProxyProto')?.value || 'off'
      };
      await saveConfigPayload(payload, 'Applied GeoIP & Proxy Protocol policy');
    });

    // Preset GeoIP Country chips on Switchboard tab
    $$('[data-geo-preset]').forEach((chip) => {
      chip.addEventListener('click', () => {
        const preset = chip.getAttribute('data-geo-preset');
        if ($('#cfgAllowedCountries')) $('#cfgAllowedCountries').value = preset;
        if ($('#quickAllowedCC')) $('#quickAllowedCC').value = preset;
      });
    });

    // Full Config Form on Switchboard tab
    $('#fullConfigForm')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        geoip_allowed_countries: $('#cfgAllowedCountries')?.value || '',
        geoip_blocked_countries: $('#cfgBlockedCountries')?.value || '',
        geoip_direction: $('#cfgGeoDirection')?.value || 'both',
        proxy_protocol: $('#cfgProxyProtocol')?.value || 'off',
        max_conn_per_external_ip: Number($('#cfgMaxConnExt')?.value || 5),
        max_conn_rate_external: Number($('#cfgMaxRateExt')?.value || 3),
        max_msgs_per_sec_external: Number($('#cfgMaxMsgsExt')?.value || 50),
        max_global_active: Number($('#cfgMaxGlobalActive')?.value || 2000),
        max_global_conn_rate: Number($('#cfgMaxGlobalRate')?.value || 500),
        web_public_domain: $('#cfgPublicDomain')?.value || ''
      };
      await saveConfigPayload(payload, 'Saved & hot-reloaded all engine parameters');
      state.formDirty = false;
    });

    $$('#fullConfigForm input, #fullConfigForm select').forEach((el) => {
      el.addEventListener('input', () => { state.formDirty = true; });
    });
  }

  async function saveConfigPayload(payload, successMsg) {
    try {
      const res = await fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.ok) {
        showToast(successMsg);
        fetchOverview();
      } else {
        showToast(data.error || 'Update failed', true);
      }
    } catch (err) {
      showToast('Failed to reach Control Plane API', true);
    }
  }

  // Fetch Overview Telemetry
  async function fetchOverview() {
    try {
      const res = await fetch('/api/overview');
      const data = await res.json();
      if (!data.ok) return;

      state.overview = data;
      state.history = data.history || [];
      state.routes = data.routes || [];
      state.events = data.events || [];
      state.layerCounts = data.layer_counts || {};
      state.config = data.config || {};

      renderHeaderAndKPIs(data);
      syncSwitchesAndInputs(data.config);
      renderLayerBars(data.layer_counts);
      renderRoutesTables(data.routes);
      renderThreatStream(data.events);
      drawTrafficChart();
    } catch (err) {
      // silent retry on next tick
    }
  }

  function renderHeaderAndKPIs(data) {
    const sys = data.system || {};
    const m = data.metrics || {};
    const cfg = data.config || {};

    $('#sysClock').textContent = data.timestamp || new Date().toTimeString().slice(0, 8);
    $('#sysVersion').textContent = sys.version || 'v3.8';
    $('#uptimeLabel').textContent = `UPTIME: ${formatDuration(sys.uptime_sec)}`;

    // Defense mode pill
    const modeText = $('#defenseModeText');
    const modeDot = $('#defenseModeChip .dot');
    const mode = sys.defense_mode || 'NORMAL';
    if (modeText) modeText.textContent = `MODE: ${mode}`;
    if (modeDot) {
      modeDot.className = 'dot ' + (mode === 'NORMAL' ? 'dot-emerald' : mode === 'ELEVATED' ? 'dot-amber' : 'dot-crimson');
    }

    // GeoIP header status
    const geoText = $('#geoHeaderText');
    const geoDot = $('#geoStatusChip .dot');
    if (geoText) {
      if (cfg.geoip_enabled) {
        geoText.textContent = `GEOIP: ${cfg.geoip_allowed_countries || 'VN'} [${(cfg.geoip_direction || 'both').toUpperCase()}]`;
        if (geoDot) geoDot.className = 'dot dot-emerald';
      } else {
        geoText.textContent = 'GEOIP: GLOBAL OPEN';
        if (geoDot) geoDot.className = 'dot dot-cyan';
      }
    }

    // KPI Cards
    $('#kpiMbpsIn').innerHTML = `${Number(m.cur_mbps_in || 0).toFixed(2)} <small>Mbps</small>`;
    $('#kpiPeakMbps').textContent = `${Number(m.peak_mbps_in || 0).toFixed(2)} Mbps`;
    $('#kpiBytesIn').textContent = formatBytes(m.bytes_in);

    $('#kpiPpsIn').innerHTML = `${m.cur_pps_in || 0} <small>pkt/s</small>`;
    $('#kpiMbpsOut').textContent = `${Number(m.cur_mbps_out || 0).toFixed(2)} Mbps`;
    $('#kpiPpsOut').textContent = `${m.cur_pps_out || 0}/s`;

    $('#kpiActiveConns').textContent = m.active_conns || 0;
    $('#kpiMaxConns').textContent = m.max_global_conns || 2000;
    $('#kpiTotalConns').textContent = m.total_conns || 0;
    $('#kpiRouteCount').textContent = (data.routes || []).length;

    $('#kpiBlockedConns').innerHTML = `${m.blocked_conns || 0} <small>drops</small>`;
    $('#kpiBlockedSubnets').textContent = m.blocked_subnets || 0;
    $('#kpiBlacklistCount').textContent = m.blacklist_count || 0;

    // Radar HUD Overlay
    const primary = (data.routes || [])[0];
    if (primary) {
      $('#hudPrimaryEndpoint').textContent = primary.endpoint;
      $('#hudPrimaryOrigin').textContent = `${primary.origin_ip}:${primary.origin_port}`;
    }
    $('#hudGeoStatus').textContent = cfg.geoip_enabled
      ? `ON (${cfg.geoip_allowed_countries || 'VN'} / ${(cfg.geoip_direction || 'both').toUpperCase()})`
      : 'OFF';
    $('#hudProxyProto').textContent = (cfg.proxy_protocol || 'off').toUpperCase();
  }

  function syncSwitchesAndInputs(cfg) {
    if (!cfg) return;
    $$('input[data-cfg-toggle]').forEach((chk) => {
      const key = chk.getAttribute('data-cfg-toggle');
      if (key in cfg) {
        chk.checked = Boolean(cfg[key]);
      }
    });

    if (document.activeElement?.id !== 'quickAllowedCC' && $('#quickAllowedCC')) {
      $('#quickAllowedCC').value = cfg.geoip_allowed_countries || 'VN';
    }
    if (document.activeElement?.id !== 'quickGeoDir' && $('#quickGeoDir')) {
      $('#quickGeoDir').value = cfg.geoip_direction || 'both';
    }
    if (document.activeElement?.id !== 'quickProxyProto' && $('#quickProxyProto')) {
      $('#quickProxyProto').value = cfg.proxy_protocol || 'off';
    }

    if (!state.formDirty) {
      if ($('#cfgAllowedCountries')) $('#cfgAllowedCountries').value = cfg.geoip_allowed_countries || '';
      if ($('#cfgBlockedCountries')) $('#cfgBlockedCountries').value = cfg.geoip_blocked_countries || '';
      if ($('#cfgGeoDirection')) $('#cfgGeoDirection').value = cfg.geoip_direction || 'both';
      if ($('#cfgProxyProtocol')) $('#cfgProxyProtocol').value = cfg.proxy_protocol || 'off';
      if ($('#cfgMaxConnExt')) $('#cfgMaxConnExt').value = cfg.max_conn_per_external_ip || 5;
      if ($('#cfgMaxRateExt')) $('#cfgMaxRateExt').value = cfg.max_conn_rate_external || 3;
      if ($('#cfgMaxMsgsExt')) $('#cfgMaxMsgsExt').value = cfg.max_msgs_per_sec_external || 50;
      if ($('#cfgMaxGlobalActive')) $('#cfgMaxGlobalActive').value = cfg.max_global_active || 2000;
      if ($('#cfgMaxGlobalRate')) $('#cfgMaxGlobalRate').value = cfg.max_global_conn_rate || 500;
      if ($('#cfgPublicDomain')) $('#cfgPublicDomain').value = cfg.web_public_domain || '';
    }
  }

  function renderLayerBars(counts) {
    const container = $('#layerBarsContainer');
    if (!container) return;

    const layers = [
      { key: 'GEOIP_BLOCK_IN', label: 'L1.5 // GeoIP Inbound International Block', alt: 'GEOIP_BLOCK_OUT' },
      { key: 'RATE_LIMIT_EXCEEDED', label: 'L2 // Per-IP & Global Connection Rate Limit', alt: 'PACKET_FLOOD' },
      { key: 'HALFOPEN_FLOOD', label: 'L3 // Half-Open SYN & Handshake Timeout', alt: 'HALFOPEN_TIMEOUT' },
      { key: 'BLACKLISTED_IP', label: 'L1 // ACL Blacklist & Auto-Ban Drop', alt: 'AUTO_BLACKLIST' },
      { key: 'SUBNET_BLOCKED', label: 'L7 // Botnet /24 & /16 Subnet Aggregation', alt: 'CLUSTER_ATTACK' },
      { key: 'SURGE_THROTTLED', label: 'L8 // Surge Protection & Lockdown Shield', alt: 'LOCKDOWN_DROP' }
    ];

    // Sum L7 signature hits
    let sigHits = 0;
    Object.keys(counts || {}).forEach((k) => {
      if (
        !['GEOIP_BLOCK_IN', 'GEOIP_BLOCK_OUT', 'RATE_LIMIT_EXCEEDED', 'PACKET_FLOOD',
          'HALFOPEN_FLOOD', 'HALFOPEN_TIMEOUT', 'BLACKLISTED_IP', 'AUTO_BLACKLIST',
          'SUBNET_BLOCKED', 'CLUSTER_ATTACK', 'SURGE_THROTTLED', 'LOCKDOWN_DROP'].includes(k)
      ) {
        sigHits += Number(counts[k] || 0);
      }
    });

    const rows = layers.map((l) => {
      const v = Number((counts && counts[l.key]) || 0) + Number((counts && counts[l.alt]) || 0);
      return { label: l.label, value: v };
    });
    rows.splice(3, 0, { label: 'L4 // Deep Packet Signature Engine (29 Rules)', value: sigHits });

    const maxVal = Math.max(1, ...rows.map((r) => r.value));
    container.innerHTML = rows.map((r) => {
      const pct = Math.min(100, Math.round((r.value / maxVal) * 100));
      return `
        <div class="layer-bar-row">
          <div class="layer-bar-head">
            <span class="layer-bar-name">${r.label}</span>
            <span class="layer-bar-val">${r.value} drops</span>
          </div>
          <div class="layer-bar-track">
            <div class="layer-bar-fill" style="width:${r.value > 0 ? Math.max(6, pct) : 2}%"></div>
          </div>
        </div>
      `;
    }).join('');
  }

  // Render Routes in both Overview & Endpoints tabs
  function renderRoutesTables(routes) {
    const ovBody = $('#overviewRoutesBody');
    const fullBody = $('#fullRoutesTableBody');
    if (!routes) return;

    if (ovBody) {
      ovBody.innerHTML = routes.map((r) => {
        const statusDot = r.enabled ? 'dot-emerald' : 'dot-crimson';
        const latText = r.last_latency_ms > 0 ? `${r.last_latency_ms} ms` : (r.origin_status === 'OFFLINE' ? 'OFFLINE' : 'READY');
        return `
          <tr>
            <td><span class="dot ${statusDot}"></span> ${r.enabled ? 'ACTIVE' : 'PAUSED'}</td>
            <td><b>${escapeHtml(r.name)}</b> ${r.is_primary ? '<span class="badge-cyan">PRIMARY</span>' : ''}</td>
            <td>
              <span class="ep-pill" data-copy="${escapeHtml(r.endpoint)}" title="Click to copy Firewall Endpoint">
                ${escapeHtml(r.endpoint)} &#10697;
              </span>
            </td>
            <td><span class="origin-pill">${escapeHtml(r.origin_ip)}:${r.origin_port}</span></td>
            <td>${latText}</td>
            <td><b>${r.active_conns}</b> active / ${r.total_conns} total</td>
            <td>
              <label class="cyber-toggle">
                <input type="checkbox" data-route-toggle="${r.id}" ${r.enabled ? 'checked' : ''} />
                <span class="slider"></span>
              </label>
            </td>
          </tr>
        `;
      }).join('');
    }

    if (fullBody) {
      fullBody.innerHTML = routes.map((r) => {
        const healthBadge = r.origin_status === 'OFFLINE'
          ? `<span class="badge-crimson">OFFLINE</span>`
          : `<span class="badge-emerald">ONLINE ${r.last_latency_ms > 0 ? `(${r.last_latency_ms}ms)` : ''}</span>`;
        return `
          <tr>
            <td>#${r.id}</td>
            <td>
              <b>${escapeHtml(r.name)}</b>
              ${r.is_primary ? '<br><span class="badge-cyan">PRIMARY CONFIG.TXT</span>' : ''}
            </td>
            <td>
              <span class="ep-pill" data-copy="${escapeHtml(r.endpoint)}" title="Click to copy endpoint for Game Client">
                ${escapeHtml(r.endpoint)} &#10697;
              </span>
            </td>
            <td><span class="origin-pill">${escapeHtml(r.origin_ip)}:${r.origin_port}</span></td>
            <td>${escapeHtml(r.protocol)} &bull; PROXY:${escapeHtml((r.proxy_protocol || 'inherit').toUpperCase())}</td>
            <td>${healthBadge}</td>
            <td>RX: ${formatBytes(r.bytes_in)}<br>TX: ${formatBytes(r.bytes_out)}</td>
            <td><b>${r.active_conns}</b> conn / <span style="color:var(--crimson)">${r.blocked_conns} drops</span></td>
            <td>
              <label class="cyber-toggle">
                <input type="checkbox" data-route-toggle="${r.id}" ${r.enabled ? 'checked' : ''} />
                <span class="slider"></span>
              </label>
            </td>
            <td>
              <div style="display:flex;gap:5px;">
                <button class="btn-ghost btn-xs" data-ping-route="${r.id}">PING</button>
                <button class="btn-ghost btn-xs" data-edit-route="${r.id}">EDIT</button>
                ${!r.is_primary ? `<button class="btn-ghost btn-xs" style="color:var(--crimson)" data-del-route="${r.id}">DEL</button>` : ''}
              </div>
            </td>
          </tr>
        `;
      }).join('');
    }

    // Bind copy pills
    $$('[data-copy]').forEach((el) => {
      el.onclick = () => copyText(el.getAttribute('data-copy'));
    });

    // Bind route ON/OFF toggles
    $$('[data-route-toggle]').forEach((chk) => {
      chk.onchange = async () => {
        const id = Number(chk.getAttribute('data-route-toggle'));
        const enabled = chk.checked;
        const res = await fetch('/api/routes', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id, enabled })
        });
        const data = await res.json();
        if (data.ok) {
          showToast(`Route #${id} ${enabled ? 'ENABLED' : 'PAUSED'}`);
          fetchOverview();
        } else {
          showToast(data.error || 'Failed to toggle route', true);
        }
      };
    });

    // Bind PING buttons
    $$('[data-ping-route]').forEach((btn) => {
      btn.onclick = async () => {
        const id = Number(btn.getAttribute('data-ping-route'));
        btn.textContent = '...';
        const res = await fetch('/api/routes/ping', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id })
        });
        const data = await res.json();
        if (data.ok && data.route) {
          showToast(`Origin ${data.route.origin_ip}:${data.route.origin_port} -> ${data.route.origin_status} (${data.route.last_latency_ms}ms)`);
          fetchOverview();
        } else {
          showToast(data.error || 'Ping failed', true);
        }
      };
    });

    // Bind EDIT buttons
    $$('[data-edit-route]').forEach((btn) => {
      btn.onclick = () => {
        const id = Number(btn.getAttribute('data-edit-route'));
        const r = state.routes.find((x) => x.id === id);
        if (!r) return;
        state.editingRouteId = r.id;
        $('#routeIdInput').value = r.id;
        $('#routeNameInput').value = r.name;
        $('#routeOriginIPInput').value = r.origin_ip;
        $('#routeOriginPortInput').value = r.origin_port;
        $('#routeDomainInput').value = r.domain;
        $('#routeListenPortInput').value = r.listen_port;
        $('#routeProtocolInput').value = r.protocol || 'TCP+SYN';
        $('#routeProxyProtoInput').value = r.proxy_protocol || 'inherit';
        $('#routeInspectInput').value = r.inspection_mode || 'strict_game';
        $('#routeFormTitle').textContent = `EDIT ROUTE #${r.id} (${r.name})`;
        $('#btnSubmitRoute').textContent = `UPDATE ROUTE #${r.id} ENDPOINT`;
        $('#btnCancelEditRoute')?.classList.remove('hidden');
        updateTunnelPreview();
      };
    });

    // Bind DELETE buttons
    $$('[data-del-route]').forEach((btn) => {
      btn.onclick = async () => {
        const id = Number(btn.getAttribute('data-del-route'));
        const res = await fetch(`/api/routes?id=${id}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.ok) {
          showToast(`Removed Route #${id}`);
          fetchOverview();
        } else {
          showToast(data.error || 'Delete failed', true);
        }
      };
    });
  }

  // Provisioning Form & Tunnel Preview
  function initRouteProvisioningForm() {
    const updatePreview = () => updateTunnelPreview();
    ['routeDomainInput', 'routeListenPortInput', 'routeOriginIPInput', 'routeOriginPortInput'].forEach((id) => {
      $(`#${id}`)?.addEventListener('input', updatePreview);
    });

    $('#btnCancelEditRoute')?.addEventListener('click', resetRouteForm);

    $('#routeForm')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const id = Number($('#routeIdInput')?.value || 0);
      const payload = {
        id,
        name: $('#routeNameInput')?.value || '',
        origin_ip: $('#routeOriginIPInput')?.value || '',
        origin_port: Number($('#routeOriginPortInput')?.value || 0),
        domain: $('#routeDomainInput')?.value || '',
        listen_port: Number($('#routeListenPortInput')?.value || 0),
        protocol: $('#routeProtocolInput')?.value || 'TCP+SYN',
        proxy_protocol: $('#routeProxyProtoInput')?.value || 'inherit',
        inspection_mode: $('#routeInspectInput')?.value || 'strict_game'
      };

      const method = id > 0 ? 'PATCH' : 'POST';
      const res = await fetch('/api/routes', {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.ok && data.route) {
        showToast(`Linked Firewall Endpoint ${data.route.endpoint} -> Origin ${data.route.origin_ip}:${data.route.origin_port}`);
        resetRouteForm();
        fetchOverview();
      } else {
        showToast(data.error || 'Failed to provision endpoint', true);
      }
    });
  }

  function resetRouteForm() {
    state.editingRouteId = 0;
    $('#routeIdInput').value = '0';
    $('#routeForm')?.reset();
    $('#routeFormTitle').textContent = 'SETUP ORIGIN SERVER & LINK FW ENDPOINT';
    $('#btnSubmitRoute').textContent = 'DEPLOY & LINK FIREWALL ENDPOINT';
    $('#btnCancelEditRoute')?.classList.add('hidden');
    updateTunnelPreview();
  }

  function updateTunnelPreview() {
    const dom = $('#routeDomainInput')?.value?.trim() || state.config.web_public_domain || 'fw.edge-node.vn';
    const lport = $('#routeListenPortInput')?.value?.trim() || 'AUTO(20001+)';
    const oip = $('#routeOriginIPInput')?.value?.trim() || '127.0.0.1';
    const oport = $('#routeOriginPortInput')?.value?.trim() || '14445';
    if ($('#previewFwEndpoint')) $('#previewFwEndpoint').textContent = `${dom}:${lport}`;
    if ($('#previewOriginTarget')) $('#previewOriginTarget').textContent = `${oip}:${oport}`;
  }

  // Origin Server Lookup Form
  function initLookupForm() {
    $('#lookupForm')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const origin_ip = $('#lookupOriginIP')?.value?.trim() || '';
      const origin_port = Number($('#lookupOriginPort')?.value || 0);
      const box = $('#lookupResultBox');
      if (!box) return;

      const res = await fetch('/api/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ origin_ip, origin_port })
      });
      const data = await res.json();
      box.classList.remove('hidden');
      if (!data.ok) {
        box.innerHTML = `<div style="color:var(--crimson);font-weight:700;">[NOT FOUND] ${escapeHtml(data.error || 'No route found')}</div>`;
        return;
      }
      const r = data.route;
      box.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
          <div>
            <div style="font-size:10px;color:var(--text-muted)">PROTECTED ROUTE #${r.id} // ${escapeHtml(r.name)}</div>
            <div style="font-size:15px;font-weight:800;color:var(--emerald);margin-top:2px;">
              FIREWALL ENDPOINT: ${escapeHtml(r.endpoint)}
            </div>
            <div style="font-size:11px;color:var(--cyan);">
              ORIGIN TARGET: ${escapeHtml(r.origin_ip)}:${r.origin_port} &bull; STATUS: ${r.origin_status} (${r.last_latency_ms}ms)
            </div>
          </div>
          <button type="button" class="btn-cyber btn-sm" id="btnCopyLookupEp">COPY ENDPOINT</button>
        </div>
      `;
      $('#btnCopyLookupEp')?.addEventListener('click', () => copyText(r.endpoint));
    });
  }

  // Threat Stream & ACL
  function renderThreatStream(events) {
    const tbody = $('#threatStreamBody');
    if (!tbody) return;
    const filter = ($('#eventFilterInput')?.value || '').toLowerCase().trim();
    const list = (events || []).slice().reverse().filter((ev) => {
      if (!filter) return true;
      return (
        (ev.ip || '').toLowerCase().includes(filter) ||
        (ev.signature || '').toLowerCase().includes(filter) ||
        (ev.details || '').toLowerCase().includes(filter)
      );
    });

    if (list.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:20px;">NO THREAT SIGNATURES DETECTED IN CURRENT WINDOW</td></tr>`;
      return;
    }

    tbody.innerHTML = list.map((ev) => {
      const badgeClass = ev.level === 'CRITICAL' || ev.level === 'HIGH' ? 'badge-crimson' : 'badge-cyan';
      return `
        <tr>
          <td>${escapeHtml(ev.timestamp)}</td>
          <td><span class="${badgeClass}">${escapeHtml(ev.level)}</span></td>
          <td><b style="color:#fff">${escapeHtml(ev.ip)}</b></td>
          <td><span style="color:var(--emerald);font-weight:700">${escapeHtml(ev.signature)}</span></td>
          <td>${escapeHtml(ev.details)}</td>
          <td>
            <button class="btn-ghost btn-xs" style="color:var(--crimson)" data-quick-ban="${escapeHtml(ev.ip)}">BAN IP</button>
          </td>
        </tr>
      `;
    }).join('');

    $$('[data-quick-ban]').forEach((btn) => {
      btn.onclick = async () => {
        const ip = btn.getAttribute('data-quick-ban');
        await updateACL('blacklist', 'add', ip, 'Manual ban from Threat Stream');
      };
    });
  }

  async function loadACL() {
    try {
      const res = await fetch('/api/acl');
      const data = await res.json();
      if (!data.ok) return;
      renderACLLists(data.whitelist || [], data.blacklist || []);
    } catch (e) {}
  }

  function renderACLLists(wl, bl) {
    if ($('#wlBadgeCount')) $('#wlBadgeCount').textContent = `${wl.length} Entries`;
    if ($('#blBadgeCount')) $('#blBadgeCount').textContent = `${bl.length} Entries`;

    const wlBox = $('#whitelistContainer');
    if (wlBox) {
      wlBox.innerHTML = wl.map((ip) => `
        <div class="acl-item">
          <span style="color:var(--emerald);font-weight:600">${escapeHtml(ip)}</span>
          ${ip !== '127.0.0.1' && ip !== '::1'
            ? `<button class="btn-ghost btn-xs" data-remove-wl="${escapeHtml(ip)}">REMOVE</button>`
            : `<span class="badge-cyan">SYSTEM</span>`}
        </div>
      `).join('');
    }

    const blBox = $('#blacklistContainer');
    if (blBox) {
      blBox.innerHTML = bl.map((item) => `
        <div class="acl-item">
          <div>
            <b style="color:var(--crimson)">${escapeHtml(item.target)}</b>
            <span style="color:var(--text-muted);font-size:10px;margin-left:6px;">${escapeHtml(item.reason)}</span>
          </div>
          <button class="btn-ghost btn-xs" data-remove-bl="${escapeHtml(item.target)}">UNBAN</button>
        </div>
      `).join('');
    }

    $$('[data-remove-wl]').forEach((b) => {
      b.onclick = () => updateACL('whitelist', 'remove', b.getAttribute('data-remove-wl'));
    });
    $$('[data-remove-bl]').forEach((b) => {
      b.onclick = () => updateACL('blacklist', 'remove', b.getAttribute('data-remove-bl'));
    });
  }

  async function updateACL(list, action, target, reason = '') {
    const res = await fetch('/api/acl', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ list, action, target, reason })
    });
    const data = await res.json();
    if (data.ok) {
      showToast(`ACL ${list.toUpperCase()}: ${action.toUpperCase()} ${target}`);
      renderACLLists(data.whitelist || [], data.blacklist || []);
      fetchOverview();
    } else {
      showToast(data.error || 'ACL operation failed', true);
    }
  }

  function initACLControls() {
    $('#addWhitelistForm')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const target = $('#wlTargetInput')?.value?.trim();
      if (!target) return;
      await updateACL('whitelist', 'add', target);
      $('#wlTargetInput').value = '';
    });

    $('#addBlacklistForm')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const target = $('#blTargetInput')?.value?.trim();
      const reason = $('#blReasonInput')?.value?.trim();
      if (!target) return;
      await updateACL('blacklist', 'add', target, reason);
      $('#blTargetInput').value = '';
      $('#blReasonInput').value = '';
    });

    $('#btnClearEvents')?.addEventListener('click', async () => {
      await fetch('/api/events/clear', { method: 'POST' });
      showToast('Cleared Threat Stream logs');
      fetchOverview();
    });

    $('#eventFilterInput')?.addEventListener('input', () => {
      renderThreatStream(state.events);
    });
  }

  // ============================================================================
  // VISUAL 1: GLOBAL CYBER THREAT RADAR & VECTOR TOPOLOGY CANVAS (#topologyCanvas)
  // ============================================================================
  function initTopologyAnimation() {
    const canvas = $('#topologyCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    function spawnParticles() {
      const cfg = state.config || {};
      const geoOn = Boolean(cfg.geoip_enabled);
      const allowedStr = (cfg.geoip_allowed_countries || 'VN').toUpperCase();

      if (state.particles.length < 34) {
        const src = GLOBAL_NODES[Math.floor(Math.random() * GLOBAL_NODES.length)];
        const isAllowedCountry = !geoOn || allowedStr.includes(src.country);
        const isAttack = !isAllowedCountry || Math.random() < 0.16;

        state.particles.push({
          sx: src.x,
          sy: src.y,
          tx: FW_CORE.x,
          ty: FW_CORE.y,
          t: 0,
          speed: 0.008 + Math.random() * 0.009,
          blocked: isAttack,
          stage: 'inbound' // 'inbound' -> 'tunnel'
        });
      }
    }

    function renderFrame() {
      const w = canvas.width;
      const h = canvas.height;
      ctx.clearRect(0, 0, w, h);

      // Cyber Coordinate Grid & Radar Rings around FW_CORE
      const cx = FW_CORE.x * w;
      const cy = FW_CORE.y * h;

      ctx.save();
      ctx.strokeStyle = 'rgba(0, 229, 255, 0.08)';
      ctx.lineWidth = 1;
      [42, 85, 135].forEach((r) => {
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.stroke();
      });

      // Rotating radar sweep line
      state.radarAngle = (state.radarAngle + 0.022) % (Math.PI * 2);
      const grad = ctx.createLinearGradient(cx, cy, cx + Math.cos(state.radarAngle) * 135, cy + Math.sin(state.radarAngle) * 135);
      grad.addColorStop(0, 'rgba(0, 255, 157, 0.32)');
      grad.addColorStop(1, 'rgba(0, 255, 157, 0)');
      ctx.strokeStyle = grad;
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(cx + Math.cos(state.radarAngle) * 135, cy + Math.sin(state.radarAngle) * 135);
      ctx.stroke();
      ctx.restore();

      // Draw static vector paths from Global Nodes -> FW Core
      GLOBAL_NODES.forEach((n) => {
        const nx = n.x * w;
        const ny = n.y * h;
        const cpx = (nx + cx) * 0.5;
        const cpy = Math.min(ny, cy) - 34;

        ctx.strokeStyle = n.domestic ? 'rgba(0, 255, 157, 0.16)' : 'rgba(0, 229, 255, 0.1)';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(nx, ny);
        ctx.quadraticCurveTo(cpx, cpy, cx, cy);
        ctx.stroke();

        // Node circle & label
        ctx.fillStyle = n.domestic ? '#00ff9d' : '#00e5ff';
        ctx.beginPath();
        ctx.arc(nx, ny, 4, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = '#89a7c7';
        ctx.font = '600 10px "JetBrains Mono", monospace';
        ctx.fillText(n.label, nx - 24, ny - 9);
      });

      // Draw Protected Tunnel: FW Core -> Origin Server
      const ox = ORIGIN_CORE.x * w;
      const oy = ORIGIN_CORE.y * h;
      ctx.strokeStyle = 'rgba(0, 229, 255, 0.42)';
      ctx.lineWidth = 2.5;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(ox, oy);
      ctx.stroke();

      // Update & Draw Moving Packet Particles
      spawnParticles();
      for (let i = state.particles.length - 1; i >= 0; i--) {
        const p = state.particles[i];
        p.t += p.speed;

        if (p.stage === 'inbound') {
          const stopAt = p.blocked ? 0.84 : 1.0;
          if (p.t >= stopAt) {
            if (p.blocked) {
              // Spawn Crimson Shield Intercept Ring
              const sx = p.sx * w, sy = p.sy * h;
              const cpx = (sx + cx) * 0.5, cpy = Math.min(sy, cy) - 34;
              const ix = (1 - stopAt) * (1 - stopAt) * sx + 2 * (1 - stopAt) * stopAt * cpx + stopAt * stopAt * cx;
              const iy = (1 - stopAt) * (1 - stopAt) * sy + 2 * (1 - stopAt) * stopAt * cpy + stopAt * stopAt * cy;
              state.shields.push({ x: ix, y: iy, r: 3, alpha: 1.0 });
              state.particles.splice(i, 1);
            } else {
              p.stage = 'tunnel';
              p.t = 0;
              p.speed = 0.022;
            }
            continue;
          }

          const sx = p.sx * w, sy = p.sy * h;
          const cpx = (sx + cx) * 0.5, cpy = Math.min(sy, cy) - 34;
          const u = 1 - p.t;
          const px = u * u * sx + 2 * u * p.t * cpx + p.t * p.t * cx;
          const py = u * u * sy + 2 * u * p.t * cpy + p.t * p.t * cy;

          ctx.fillStyle = p.blocked ? '#ff2a54' : '#00ff9d';
          ctx.shadowColor = p.blocked ? '#ff2a54' : '#00ff9d';
          ctx.shadowBlur = 8;
          ctx.beginPath();
          ctx.arc(px, py, p.blocked ? 3.2 : 2.8, 0, Math.PI * 2);
          ctx.fill();
          ctx.shadowBlur = 0;
        } else {
          // Forwarding along Protected Tunnel -> Origin Server
          if (p.t >= 1.0) {
            state.particles.splice(i, 1);
            continue;
          }
          const px = cx + (ox - cx) * p.t;
          const py = cy + (oy - cy) * p.t;
          ctx.fillStyle = '#00e5ff';
          ctx.shadowColor = '#00e5ff';
          ctx.shadowBlur = 8;
          ctx.beginPath();
          ctx.arc(px, py, 3, 0, Math.PI * 2);
          ctx.fill();
          ctx.shadowBlur = 0;
        }
      }

      // Draw Shield Intercept Explosions
      for (let i = state.shields.length - 1; i >= 0; i--) {
        const s = state.shields[i];
        s.r += 0.7;
        s.alpha -= 0.04;
        if (s.alpha <= 0) {
          state.shields.splice(i, 1);
          continue;
        }
        ctx.strokeStyle = `rgba(255, 42, 84, ${s.alpha})`;
        ctx.lineWidth = 1.6;
        ctx.beginPath();
        ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
        ctx.stroke();
      }

      // Draw FW Core Hub & Origin Core Hub
      ctx.fillStyle = '#00ff9d';
      ctx.beginPath();
      ctx.arc(cx, cy, 8, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = '#ffffff';
      ctx.font = '700 11px "JetBrains Mono", monospace';
      ctx.fillText(FW_CORE.label, cx - 44, cy + 24);

      ctx.fillStyle = '#00e5ff';
      ctx.beginPath();
      ctx.arc(ox, oy, 7, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = '#ffffff';
      ctx.fillText(ORIGIN_CORE.label, ox - 45, oy + 24);

      requestAnimationFrame(renderFrame);
    }

    requestAnimationFrame(renderFrame);
  }

  // ============================================================================
  // VISUAL 2: 180-SECOND BANDWIDTH & PPS OSCILLOSCOPE (#trafficCanvas)
  // ============================================================================
  function initTrafficChartEvents() {
    const canvas = $('#trafficCanvas');
    const tooltip = $('#chartTooltip');
    if (!canvas || !tooltip) return;

    canvas.addEventListener('mousemove', (e) => {
      const rect = canvas.getBoundingClientRect();
      const relX = (e.clientX - rect.left) / rect.width;
      const pts = state.history || [];
      if (!pts.length) return;
      const idx = Math.min(pts.length - 1, Math.max(0, Math.floor(relX * pts.length)));
      state.hoverIndex = idx;
      drawTrafficChart();

      const pt = pts[idx];
      if (pt) {
        const valIn = formatUnitValue(pt, 'in');
        const valOut = formatUnitValue(pt, 'out');
        tooltip.classList.remove('hidden');
        tooltip.style.left = `${Math.min(rect.width - 180, Math.max(10, e.clientX - rect.left + 12))}px`;
        tooltip.style.top = `14px`;
        tooltip.innerHTML = `
          <div style="color:var(--cyan);font-weight:700">${pt.time}</div>
          <div style="color:var(--emerald)">RX IN: ${valIn}</div>
          <div style="color:#00e5ff">TX OUT: ${valOut}</div>
          <div style="color:var(--crimson)">DROPS: ${pt.blocked}/s</div>
        `;
      }
    });

    canvas.addEventListener('mouseleave', () => {
      state.hoverIndex = -1;
      tooltip.classList.add('hidden');
      drawTrafficChart();
    });
  }

  function formatUnitValue(pt, dir) {
    if (state.unit === 'pps') {
      return `${dir === 'in' ? pt.pps_in : pt.pps_out} pkt/s`;
    }
    const mbps = dir === 'in' ? pt.mbps_in : pt.mbps_out;
    if (state.unit === 'gbps') {
      return `${(mbps / 1000).toFixed(4)} Gbps`;
    }
    return `${Number(mbps || 0).toFixed(2)} Mbps`;
  }

  function getPointScalar(pt, dir) {
    if (state.unit === 'pps') return dir === 'in' ? (pt.pps_in || 0) : (pt.pps_out || 0);
    const mbps = dir === 'in' ? (pt.mbps_in || 0) : (pt.mbps_out || 0);
    return state.unit === 'gbps' ? mbps / 1000 : mbps;
  }

  function drawTrafficChart() {
    const canvas = $('#trafficCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    const padL = 56, padR = 18, padT = 18, padB = 26;
    const plotW = w - padL - padR;
    const plotH = h - padT - padB;

    ctx.clearRect(0, 0, w, h);

    const pts = state.history || [];
    let maxVal = 1;
    pts.forEach((p) => {
      maxVal = Math.max(maxVal, getPointScalar(p, 'in'), getPointScalar(p, 'out'));
    });
    maxVal *= 1.18;

    // Horizontal Grid Lines
    ctx.strokeStyle = 'rgba(0, 229, 255, 0.08)';
    ctx.fillStyle = '#6f8aa8';
    ctx.font = '10px "JetBrains Mono", monospace';
    for (let i = 0; i <= 4; i++) {
      const y = padT + (plotH * i) / 4;
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(w - padR, y);
      ctx.stroke();

      const labelVal = maxVal * (1 - i / 4);
      const txt = state.unit === 'pps' ? Math.round(labelVal).toString() : labelVal.toFixed(2);
      ctx.fillText(txt, 8, y + 3);
    }

    if (pts.length < 2) return;

    // Helper to plot area curve
    const plotCurve = (dir, strokeColor, fillTop) => {
      ctx.beginPath();
      pts.forEach((p, idx) => {
        const x = padL + (idx / (pts.length - 1)) * plotW;
        const v = getPointScalar(p, dir);
        const y = padT + plotH - (v / maxVal) * plotH;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.strokeStyle = strokeColor;
      ctx.lineWidth = 2;
      ctx.stroke();

      // Fill area under curve
      ctx.lineTo(padL + plotW, padT + plotH);
      ctx.lineTo(padL, padT + plotH);
      ctx.closePath();
      const grad = ctx.createLinearGradient(0, padT, 0, padT + plotH);
      grad.addColorStop(0, fillTop);
      grad.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = grad;
      ctx.fill();
    };

    plotCurve('out', '#00e5ff', 'rgba(0, 229, 255, 0.20)');
    plotCurve('in', '#00ff9d', 'rgba(0, 255, 157, 0.28)');

    // Crosshair on hover
    if (state.hoverIndex >= 0 && state.hoverIndex < pts.length) {
      const hx = padL + (state.hoverIndex / (pts.length - 1)) * plotW;
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.35)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(hx, padT);
      ctx.lineTo(hx, padT + plotH);
      ctx.stroke();
    }
  }

  function escapeHtml(str) {
    return String(str ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // Boot
  window.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initUnitSwitcher();
    initConfigSwitches();
    initRouteProvisioningForm();
    initLookupForm();
    initACLControls();
    initTopologyAnimation();
    initTrafficChartEvents();
    updateTunnelPreview();
    fetchOverview();
    setInterval(fetchOverview, 1200);
  });
})();
