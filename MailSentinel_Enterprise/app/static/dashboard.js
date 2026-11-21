(() => {
  'use strict';
  const $ = (selector, root = document) => root.querySelector(selector);
  const threatItems = [...document.querySelectorAll('#threatLegend .legend-row[data-index]')];
  const threatDonut = $('#threatDonut');
  const threatPalette = ['#7968dc', '#68a9e8', '#59b9ad', '#dfb45f', '#b56b9c', '#df7189', '#9b83d7', '#78a6b8'];

  function setDonut(element, values, colors) {
    if (!element) return;
    const total = values.reduce((sum, value) => sum + value, 0);
    if (!total) {
      element.style.background = 'conic-gradient(#30394a 0deg 360deg)';
      return;
    }
    let current = 0;
    const segments = values.map((value, index) => {
      const start = current;
      current += (value / total) * 360;
      return `${colors[index % colors.length]} ${start.toFixed(2)}deg ${current.toFixed(2)}deg`;
    });
    element.style.background = `conic-gradient(${segments.join(',')})`;
  }

  const threatValues = threatItems.map(item => Number($('b', item)?.textContent || 0));
  setDonut(threatDonut, threatValues, threatPalette);
  threatItems.forEach((item, index) => {
    item.addEventListener('click', () => {
      const hidden = item.classList.toggle('muted');
      const visibleValues = threatItems.map((row, i) => row.classList.contains('muted') ? 0 : threatValues[i]);
      setDonut(threatDonut, visibleValues, threatPalette);
      const centerValue = $('.donut-hole strong', threatDonut);
      if (centerValue) centerValue.textContent = visibleValues.reduce((sum, value) => sum + value, 0);
      item.setAttribute('aria-pressed', String(!hidden));
    });
  });

  const remediationRows = [...document.querySelectorAll('#remediationLegend .legend-row')];
  const remediationDonut = $('#remediationDonut');
  const remediationValues = remediationRows.map(row => Number($('b', row)?.textContent || 0));
  const remediationColors = remediationRows.map(row => getComputedStyle($('i', row)).getPropertyValue('--legend-color').trim() || '#64748b');
  setDonut(remediationDonut, remediationValues, remediationColors);

  const chartHost = $('#activityChart');
  const svg = $('#activitySvg');
  const tooltip = $('#activityTooltip');
  const periodButtons = [...document.querySelectorAll('.period-switch button')];
  const rangeLabel = $('#activityRange');
  const NS = 'http://www.w3.org/2000/svg';
  let lastData = null;

  function svgNode(name, attrs = {}) {
    const node = document.createElementNS(NS, name);
    Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, String(value)));
    return node;
  }

  function drawActivity(data) {
    if (!svg || !data || !Array.isArray(data.labels)) return;
    lastData = data;
    svg.replaceChildren();
    const width = 900, height = 230, left = 38, right = 12, top = 16, bottom = 34;
    const plotW = width - left - right, plotH = height - top - bottom;
    const allValues = [...(data.emails || []), ...(data.threats || []), ...(data.suspicious || [])].map(Number);
    const max = Math.max(4, ...allValues);
    const yMax = Math.ceil(max / 4) * 4;
    const x = index => left + (data.labels.length <= 1 ? plotW / 2 : (index / (data.labels.length - 1)) * plotW);
    const y = value => top + plotH - (Number(value || 0) / yMax) * plotH;

    for (let tick = 0; tick <= 4; tick++) {
      const val = (yMax / 4) * tick;
      const yy = y(val);
      svg.appendChild(svgNode('line', { x1: left, x2: width - right, y1: yy, y2: yy, class: 'grid-line' }));
      const label = svgNode('text', { x: left - 10, y: yy + 3, 'text-anchor': 'end', class: 'axis-label' });
      label.textContent = String(Math.round(val)); svg.appendChild(label);
    }

    const series = [
      { key: 'emails', color: '#6ca4ef', fill: 'rgba(108,164,239,.12)' },
      { key: 'threats', color: '#e36c83', fill: 'none' },
      { key: 'suspicious', color: '#dfb45f', fill: 'none' },
    ];
    series.forEach((item, seriesIndex) => {
      const values = data[item.key] || [];
      const coords = values.map((value, index) => [x(index), y(value)]);
      if (!coords.length) return;
      const lineD = coords.map((point, index) => `${index ? 'L' : 'M'} ${point[0]} ${point[1]}`).join(' ');
      if (seriesIndex === 0) {
        const areaD = `${lineD} L ${coords[coords.length - 1][0]} ${top + plotH} L ${coords[0][0]} ${top + plotH} Z`;
        svg.appendChild(svgNode('path', { d: areaD, fill: item.fill, class: 'activity-area' }));
      }
      svg.appendChild(svgNode('path', { d: lineD, fill: 'none', stroke: item.color, 'stroke-width': seriesIndex === 0 ? 2.8 : 2.1, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', class: 'activity-line' }));
      coords.forEach((point, index) => {
        const circle = svgNode('circle', { cx: point[0], cy: point[1], r: seriesIndex === 0 ? 3.2 : 2.5, fill: item.color, class: 'activity-point', tabindex: '0', role: 'img', 'aria-label': `${data.labels[index]}: ${item.key} ${values[index] || 0}` });
        circle.addEventListener('mouseenter', event => showTooltip(event, index));
        circle.addEventListener('focus', event => showTooltip(event, index));
        circle.addEventListener('mouseleave', hideTooltip);
        circle.addEventListener('blur', hideTooltip);
        svg.appendChild(circle);
      });
    });

    const step = data.labels.length > 20 ? 3 : data.labels.length > 12 ? 2 : 1;
    data.labels.forEach((label, index) => {
      if (index % step !== 0 && index !== data.labels.length - 1) return;
      const text = svgNode('text', { x: x(index), y: height - 8, 'text-anchor': 'middle', class: 'axis-label' });
      text.textContent = label; svg.appendChild(text);
    });
    if (rangeLabel) rangeLabel.textContent = data.period === 'weekly' ? 'Last 12 weeks' : data.period === 'monthly' ? 'Last 12 months' : 'Last 14 days';
  }

  function showTooltip(event, index) {
    if (!tooltip || !lastData) return;
    const label = lastData.labels[index];
    tooltip.innerHTML = `<strong>${escapeHtml(label)}</strong><span>Emails analyzed: <b>${Number(lastData.emails[index] || 0)}</b></span><span>Threats detected: <b>${Number(lastData.threats[index] || 0)}</b></span><span>Suspicious: <b>${Number(lastData.suspicious[index] || 0)}</b></span>`;
    tooltip.hidden = false;
    const rect = chartHost.getBoundingClientRect();
    const pointRect = event.target.getBoundingClientRect();
    tooltip.style.left = `${Math.min(Math.max(8, pointRect.left - rect.left), rect.width - 165)}px`;
    tooltip.style.top = `${Math.max(0, pointRect.top - rect.top - 88)}px`;
  }
  function hideTooltip() { if (tooltip) tooltip.hidden = true; }
  function escapeHtml(value) { return String(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char])); }

  async function loadPeriod(period) {
    periodButtons.forEach(button => {
      const active = button.dataset.period === period;
      button.classList.toggle('active', active);
      button.setAttribute('aria-pressed', String(active));
    });
    if (!chartHost) return;
    svg?.classList.add('loading');
    try {
      const response = await fetch(`${chartHost.dataset.endpoint}?period=${encodeURIComponent(period)}`, { headers: { 'Accept': 'application/json' } });
      if (!response.ok) throw new Error(`Activity request failed (${response.status})`);
      drawActivity(await response.json());
    } catch (error) {
      if (svg) svg.innerHTML = '<text x="450" y="115" text-anchor="middle" class="axis-label">Unable to load activity data. Refresh the page to retry.</text>';
    } finally {
      svg?.classList.remove('loading');
    }
  }
  periodButtons.forEach(button => button.addEventListener('click', () => loadPeriod(button.dataset.period)));
  if (chartHost) loadPeriod('daily');
})();
