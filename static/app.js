"use strict";

const form = document.getElementById("scan-form");
const targetInput = document.getElementById("target");
const submitBtn = document.getElementById("submit");
const resultsEl = document.getElementById("results");
const requestErrorEl = document.getElementById("request-error");

function formatTime(iso) {
  // Timestamps arrive as UTC; render them readably without pretending to
  // know the viewer's intent about timezones.
  return new Date(iso).toISOString().replace("T", " ").replace(".000Z", " UTC");
}

/** Render a list of ports as chips, or an explicit "none" note. */
function renderPorts(container, ports, className, emptyText) {
  container.innerHTML = "";
  if (!ports.length) {
    const none = document.createElement("span");
    none.className = "none";
    none.textContent = emptyText;
    container.appendChild(none);
    return;
  }
  for (const port of ports) {
    const chip = document.createElement("span");
    chip.className = className ? `port ${className}` : "port";
    chip.textContent = port;
    container.appendChild(chip);
  }
}

function renderDiff(container, diff) {
  if (!diff.added.length && !diff.removed.length) {
    const note = document.createElement("span");
    note.className = "none";
    note.textContent = "No ports opened or closed since the previous scan.";
    container.appendChild(note);
    return;
  }

  for (const [label, ports, css] of [
    ["Opened", diff.added, "add"],
    ["Closed", diff.removed, "rem"],
  ]) {
    if (!ports.length) continue;
    const row = document.createElement("div");
    row.className = "diff-row";

    const tag = document.createElement("span");
    tag.className = "diff-label";
    tag.textContent = label;

    const list = document.createElement("div");
    list.className = "ports";
    renderPorts(list, ports, css, "");

    row.append(tag, list);
    container.appendChild(row);
  }
}

const HISTORY_PAGE_SIZE = 10;

function renderHistoryTable(container, scans) {
  const totalPages = Math.max(1, Math.ceil(scans.length / HISTORY_PAGE_SIZE));
  let page = 0;

  const backToLatest = document.createElement("button");
  backToLatest.type = "button";
  backToLatest.className = "history-toggle hidden";
  backToLatest.textContent = "Back to latest";
  container.appendChild(backToLatest);

  const table = document.createElement("table");
  const thead = document.createElement("thead");
  thead.innerHTML = "<tr><th>Scanned at (UTC)</th><th>Open ports</th></tr>";
  const tbody = document.createElement("tbody");
  table.append(thead, tbody);
  container.appendChild(table);

  const nav = document.createElement("div");
  nav.className = "history-nav";

  const prevBtn = document.createElement("button");
  prevBtn.type = "button";
  prevBtn.className = "history-toggle";
  prevBtn.textContent = "Previous";

  const pageLabel = document.createElement("span");
  pageLabel.className = "history-page-label";

  const nextBtn = document.createElement("button");
  nextBtn.type = "button";
  nextBtn.className = "history-toggle";
  nextBtn.textContent = "Next";

  nav.append(prevBtn, pageLabel, nextBtn);
  if (totalPages > 1) container.appendChild(nav);

  function renderPage() {
    tbody.innerHTML = "";
    const start = page * HISTORY_PAGE_SIZE;
    const pageScans = scans.slice(start, start + HISTORY_PAGE_SIZE);

    for (const scan of pageScans) {
      const row = document.createElement("tr");

      const when = document.createElement("td");
      when.className = "time";
      when.textContent = formatTime(scan.scanned_at);

      const ports = document.createElement("td");
      renderPorts(ports, scan.open_ports, "", "no open ports");

      row.append(when, ports);
      tbody.appendChild(row);
    }

    // Only pad when pages exist to compare against — an under-full lone
    // page has nothing to jump between, so it can size to its own content.
    if (totalPages > 1) {
      for (let i = pageScans.length; i < HISTORY_PAGE_SIZE; i++) {
        const filler = document.createElement("tr");
        filler.className = "history-filler";
        filler.innerHTML = "<td>&nbsp;</td><td>&nbsp;</td>";
        tbody.appendChild(filler);
      }
    }

    pageLabel.textContent = `Page ${page + 1} of ${totalPages}`;
    prevBtn.disabled = page === 0;
    nextBtn.disabled = page >= totalPages - 1;
    backToLatest.classList.toggle("hidden", page === 0);
  }

  prevBtn.addEventListener("click", () => {
    if (page > 0) {
      page -= 1;
      renderPage();
    }
  });
  nextBtn.addEventListener("click", () => {
    if (page < totalPages - 1) {
      page += 1;
      renderPage();
    }
  });
  backToLatest.addEventListener("click", () => {
    page = 0;
    renderPage();
  });

  renderPage();
}

/** One card per target: open ports + diff + history, or the target's error. */
function buildResultCard(item) {
  const card = document.createElement("section");
  card.className = item.ok ? "result" : "result error";

  const heading = document.createElement("h2");
  heading.textContent = item.ok ? `Open ports — ${item.target}` : item.target;
  card.appendChild(heading);

  if (!item.ok) {
    const message = document.createElement("p");
    message.className = "error-message";
    message.textContent = item.error;
    card.appendChild(message);
    return card;
  }

  const scan = item.result.current_scan;

  const ports = document.createElement("div");
  ports.className = "ports";
  renderPorts(ports, scan.open_ports, "", "No open ports found in range 0-1000.");
  card.appendChild(ports);

  const time = document.createElement("p");
  time.className = "sub scan-time";
  time.textContent = "Scanned at " + formatTime(scan.scanned_at);
  card.appendChild(time);

  const diffHeading = document.createElement("h3");
  diffHeading.textContent = "Changes since previous scan";
  card.appendChild(diffHeading);
  const diffBody = document.createElement("div");
  renderDiff(diffBody, item.result.diff);
  card.appendChild(diffBody);

  const historyHeading = document.createElement("h3");
  historyHeading.textContent = "Scan history";
  card.appendChild(historyHeading);
  renderHistoryTable(card, item.result.history);

  return card;
}

function renderResults(results) {
  resultsEl.innerHTML = "";
  for (const item of results) {
    resultsEl.appendChild(buildResultCard(item));
  }
}

function showRequestError(message) {
  requestErrorEl.textContent = message;
  requestErrorEl.classList.remove("hidden");
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const targets = targetInput.value
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);

  resultsEl.innerHTML = "";

  if (!targets.length) {
    showRequestError("Enter at least one IP address or hostname.");
    return;
  }
  requestErrorEl.classList.add("hidden");
  submitBtn.disabled = true;

  let dots = 0;
  submitBtn.innerHTML = 'Scanning<span class="btn-dots"></span>';
  const dotsEl = submitBtn.querySelector(".btn-dots");
  const spinner = setInterval(() => {
    dots = (dots + 1) % 4;
    dotsEl.textContent = ".".repeat(dots);
  }, 400);

  try {
    let response;
    try {
      response = await fetch("/v1/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targets }),
      });
    } catch (err) {
      console.error("POST /v1/scans — network error (no response received):", err);
      showRequestError("Could not reach the server. Is it still running?");
      return;
    }

    let data;
    try {
      data = await response.json();
    } catch (err) {
      // e.g. a 500 with a plain-text body (unhandled server error, DB down, etc.)
      console.error(`POST /v1/scans -> ${response.status} — response body was not JSON:`, err);
      showRequestError(`Server returned ${response.status} with an unreadable response.`);
      return;
    }

    if (!response.ok) {
      console.error(`POST /v1/scans -> ${response.status}:`, data.detail || data);
      showRequestError(data.detail || "Scan failed.");
      return;
    }

    renderResults(data.results);
  } finally {
    clearInterval(spinner);
    submitBtn.disabled = false;
    submitBtn.textContent = "Scan";
  }
});
