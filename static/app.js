// app.js
// Connects the webpage buttons to our Python server

const SAMPLES = {
  safe: "Hi! Your 1-year product warranty registration is complete. Have a great day!",
  paypal: "Dear Customer, unauthorized transaction of $489.99 on your PayPal account. Account will be suspended within 24 hours unless you cancel at https://p\u0430ypal.com/login",
  usps: "USPS Urgent Notice: Your package cannot be delivered due to an incomplete address. Pay the $1.99 redelivery fee within 12 hours at https://usps.com.track-redelivery-usa.xyz/login",
  irs: "FINAL WARNING: IRS warrant issued for back taxes. Verify your Social Security Number or pay with Apple gift cards immediately at http://192.168.45.210/irs",
  fbi: "URGENT NOTICE: The FBI Cyber Division has frozen your bank account due to suspicious activity. Transfer funds to a Bitcoin wallet within 12 hours to avoid arrest: https://fbi-gov-case-verify.top/portal",
  ezpass: "E-ZPass Notice: You have an overdue toll balance of $6.50. Kindly pay within 12 hours to avoid late fees and license suspension at https://ezpass-toll-invoice.xyz/pay",
  job: "Hi! We are hiring for a remote part-time job. Earn $500 a day with daily salary paid per task. Message us on WhatsApp to apply at https://bit.ly/3xEasyJob",
  geeksquad: "Geek Squad Alert: Your subscription auto-renewal of $499.99 was processed. Call to cancel subscription immediately at 1-888-555-0199.",
  amazon: "Amazon Alert: Unusual sign-in detected. Verify your account immediately at https://arnazon.com/verify"
};

let lastResult = null;

function loadSample(name) {
  document.getElementById("messageInput").value = SAMPLES[name];
  checkMessage();
}

function clearBox() {
  document.getElementById("messageInput").value = "";
  document.getElementById("resultBox").className = "box hidden";
  document.getElementById("xrayBox").className = "box hidden";
}

async function pasteClipboard() {
  try {
    const text = await navigator.clipboard.readText();
    if (text) {
      document.getElementById("messageInput").value = text;
      checkMessage();
    }
  } catch (err) {
    alert("Please tap and hold inside the text box to paste your message.");
  }
}

async function copyReport() {
  if (!lastResult) {
    alert("Please analyze a message first.");
    return;
  }
  let reportText = "Fish Bite Assessment: " + lastResult.verdict + " (Risk Score: " + lastResult.overall_score + "/100)\n";
  reportText += "Classification: " + lastResult.scam_type + "\n";
  reportText += "Recommendation: " + lastResult.advice + "\n";
  if (lastResult.reasons.length > 0) {
    reportText += "Risk Factors:\n- " + lastResult.reasons.join("\n- ");
  }
  try {
    await navigator.clipboard.writeText(reportText);
    const btn = document.getElementById("copyBtn");
    btn.innerText = "Copied!";
    setTimeout(function () {
      btn.innerText = "Copy Report";
    }, 2000);
  } catch (err) {
    alert("Could not copy automatically.");
  }
}

function toggleLargeText() {
  document.body.classList.toggle("large-text");
  const isOn = document.body.classList.contains("large-text");
  if (isOn) {
    document.getElementById("largeTextBtn").innerText = "Large Text: ON";
  } else {
    document.getElementById("largeTextBtn").innerText = "Large Text: OFF";
  }
}

function readAloud() {
  if (!lastResult) {
    alert("Please analyze a message first.");
    return;
  }
  window.speechSynthesis.cancel();
  const speech = "Assessment: " + lastResult.verdict + ". Risk score " + lastResult.overall_score + " out of 100. " + lastResult.advice + " Please remember Fish Bite is an advisory tool and does not guarantee results.";
  window.speechSynthesis.speak(new SpeechSynthesisUtterance(speech));
}

function escapeHtml(text) {
  return String(text ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeRegExp(text) {
  return String(text ?? "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function checkMessage() {
  const text = document.getElementById("messageInput").value.trim();
  if (!text) return;

  const response = await fetch("/api/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text: text })
  });
  if (!response.ok) return;
  const data = await response.json();
  lastResult = data;
  showResults(data);
}

function showResults(data) {
  const safeColor = ["green", "yellow", "red"].includes(data.verdict_color) ? data.verdict_color : "green";
  document.getElementById("resultBox").className = "box " + safeColor;
  document.getElementById("verdictText").innerText = data.verdict;
  document.getElementById("scoreText").innerText = data.overall_score;
  document.getElementById("scamTypeText").innerText = data.scam_type;
  document.getElementById("adviceText").innerText = "Recommendation: " + data.advice;

  // Escape HTML first to prevent XSS, then highlight matched words inside the message
  let msgHtml = escapeHtml(data.input_text);
  for (let i = 0; i < data.matched_words.length; i++) {
    const safeWord = escapeHtml(data.matched_words[i]);
    if (safeWord) {
      const pattern = new RegExp(escapeRegExp(safeWord), "gi");
      msgHtml = msgHtml.replace(pattern, "<span class='bad-char'>$&</span>");
    }
  }
  document.getElementById("highlightedText").innerHTML = msgHtml;

  // Show official company website & phone number if a brand was mentioned
  const brandBox = document.getElementById("brandHelpBox");
  if (data.verified_brand_help) {
    const b = data.verified_brand_help;
    const safeBrand = escapeHtml(b.brand);
    const safeDomain = escapeHtml(b.official_domain);
    const safePhone = escapeHtml(b.official_phone);
    brandBox.className = "brand-help";
    brandBox.innerHTML =
      "<b>Verified " + safeBrand + " Reference:</b> " +
      "Official Website: <a href='https://" + safeDomain + "' target='_blank' rel='noopener noreferrer'><b>https://" + safeDomain + "</b></a> | " +
      "Official Phone: <a href='tel:" + safePhone + "'><b>" + safePhone + "</b></a>";
  } else {
    brandBox.className = "brand-help hidden";
  }

  // Show reporting box if score is 20 or higher
  const reportBox = document.getElementById("reportScamBox");
  if (data.overall_score >= 20) {
    reportBox.className = "report-scam-box";
  } else {
    reportBox.className = "report-scam-box hidden";
  }

  // Show bullet list of reasons using textContent to prevent XSS
  const list = document.getElementById("reasonsList");
  list.innerHTML = "";
  if (data.reasons.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No automated risk indicators or deceptive URL patterns were triggered.";
    list.appendChild(li);
  } else {
    for (let i = 0; i < data.reasons.length; i++) {
      const li = document.createElement("li");
      li.textContent = data.reasons[i];
      list.appendChild(li);
    }
  }

  // Show Side-by-Side URL X-Ray table with escaped fields
  const xrayBox = document.getElementById("xrayBox");
  const xrayContent = document.getElementById("xrayContent");
  xrayContent.innerHTML = "";

  if (data.urls.length > 0) {
    xrayBox.className = "box";
    for (let i = 0; i < data.urls.length; i++) {
      const u = data.urls[i];
      const safeRawUrl = escapeHtml(u.raw_url);
      const safeRealDomain = escapeHtml(u.real_domain);
      const safeScheme = escapeHtml(u.scheme);
      const safeSubdomain = escapeHtml(u.subdomain);
      const safeDomain = escapeHtml(u.domain);
      const safeTld = escapeHtml(u.tld);
      const safePath = escapeHtml(u.path);

      const shownUrl = safeRawUrl
        .replace("\u0430", "<span class='bad-char'>\u0430 (Cyrillic 'a')</span>")
        .replace("rn", "<span class='bad-char'>rn (mimics 'm')</span>");

      xrayContent.innerHTML += `
        <div class="xray-columns">
          <div class="xray-side"><b>Displayed Link Text:</b><br><code>${shownUrl}</code></div>
          <div class="xray-side"><b>Actual Registered Host (X-Ray):</b><br>Registered Domain: <b>${safeRealDomain}</b></div>
        </div>
        <div class="table-scroll">
          <table class="url-table">
            <tr><th>Protocol</th><th>Subdomain</th><th>Primary Domain</th><th>TLD</th><th>Path</th></tr>
            <tr><td>${safeScheme}://</td><td>${safeSubdomain}</td><td><b>${safeDomain}</b></td><td><b>${safeTld}</b></td><td>${safePath}</td></tr>
          </table>
        </div><br>
      `;
    }
  } else {
    xrayBox.className = "box hidden";
  }
}

// Fill the bottom table with our verified companies list
async function loadTrustedBrands() {
  const response = await fetch("/api/brands");
  if (!response.ok) return;
  const data = await response.json();
  const table = document.getElementById("brandsTable");

  for (const name in data.brands) {
    const info = data.brands[name];
    const safeName = escapeHtml(name.toUpperCase());
    const safeCategory = escapeHtml(info.category);
    const safeDomain = escapeHtml(info.domain);
    const safePhone = escapeHtml(info.phone);
    table.innerHTML += `
      <tr>
        <td><b>${safeName}</b></td>
        <td>${safeCategory}</td>
        <td><a href="https://${safeDomain}" target="_blank" rel="noopener noreferrer">https://${safeDomain}</a></td>
        <td><a href="tel:${safePhone}">${safePhone}</a></td>
      </tr>
    `;
  }
}

loadTrustedBrands();
