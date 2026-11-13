// 競走馬の格指数（スマホ用）。PC の keiba/career.py・keiba/favorites.py の画面を、ブラウザだけで組み立てる。
// データは python -m keiba.mobile が書き出す data/ の JSON。予想（ev・買い目）は入れていない。
(function () {
'use strict';
var app = document.getElementById('app');
var META = null, INDEX = null, BY_ID = null, CACHE = {};
var NEW_DAYS = 3, PAGE_SIZE = 20, AVG_MIN_RUNS = 3;

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
    return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
  });
}
function idx(v) { return v == null ? null : Math.max(100, Math.min(999, Math.round((v - 60) * 15))); }
function rankOf(i) {
  if (i == null) { return null; }
  for (var k = 0; k < META.ranks.length; k++) { if (i >= META.ranks[k][0]) { return META.ranks[k][1]; } }
  return null;
}
function confidence(rated) {     // 信頼度のラベル（rating.confidence_of と同じ。決まりは meta.json の confidence）
  if (!rated) { return ''; }
  var rules = META.confidence || [];
  for (var k = 0; k < rules.length; k++) { if (rated <= rules[k][0]) { return rules[k][1]; } }
  return '';
}
function oldEquiv(i, age, month) {     // 古馬換算（rating.old_equiv と同じ。伸びの表は meta.json の old_growth）
  if (i == null || !age || !month || age >= 4) { return i; }
  var table = (META.old_growth || {})[String(age)];
  return table ? Math.min(999, i + table[month - 1]) : i;
}
function badge(i) {
  if (i == null) { return "<span class='nk'>―</span>"; }
  var name = rankOf(i);
  return "<span class='kk kk-" + name + "'><b>" + name + '</b>' + i + '</span>';
}
function shard(key) {
  var h = 0, s = String(key);
  for (var i = 0; i < s.length; i++) { h = (h * 31 + s.charCodeAt(i)) % 1000003; }
  return h % META.shards;
}
function today() {
  var d = new Date();
  return d.getFullYear() + '-' + ('0' + (d.getMonth() + 1)).slice(-2) + '-' + ('0' + d.getDate()).slice(-2);
}
function md(day) { return (day || '').slice(5).replace('-', '/'); }
function currentGeneration() { var d = new Date(); return d.getMonth() + 1 >= 6 ? d.getFullYear() + 1 : d.getFullYear(); }
function foreign(id) { return String(id).slice(4, 6) === '19'; }

// ---- 暗号を解く（keiba/mobile.py の encrypt の逆）。データは公開の場所に置いてあるが、合言葉がないと読めない ----
var KEY = null, BLOCK = 255 * 32;
function b64(bytes) { var s = ''; bytes.forEach(function (b) { s += String.fromCharCode(b); }); return btoa(s); }
function unb64(s) { return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); }); }
function hex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ('0' + b.toString(16)).slice(-2); }).join(''); }
function deriveKey(passphrase) {     // 合言葉 → 鍵（PBKDF2-SHA256）
  var enc = new TextEncoder();
  return crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveBits']).then(function (k) {
    return crypto.subtle.deriveBits({name: 'PBKDF2', hash: 'SHA-256', salt: hexBytes(META.salt), iterations: META.rounds}, k, 256);
  }).then(function (bits) { return new Uint8Array(bits); });
}
function hexBytes(s) { var out = new Uint8Array(s.length / 2); for (var i = 0; i < out.length; i++) { out[i] = parseInt(s.substr(i * 2, 2), 16); } return out; }
function checkKey(raw) {     // 合言葉が合っているか（meta.json の check と同じになるか）
  return crypto.subtle.importKey('raw', raw, {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']).then(function (k) {
    return crypto.subtle.sign('HMAC', k, new TextEncoder().encode('keiba-kaku-check'));
  }).then(function (sig) { return hex(sig) === META.check; });
}
function decrypt(buf) {
  var data = new Uint8Array(buf), nonce = data.slice(0, 16), cipher = data.slice(16);
  return crypto.subtle.importKey('raw', KEY, 'HKDF', false, ['deriveBits']).then(function (k) {
    var jobs = [];
    for (var i = 0; i * BLOCK < cipher.length; i++) {
      var info = new Uint8Array([i >>> 24 & 255, i >>> 16 & 255, i >>> 8 & 255, i & 255]);
      jobs.push(crypto.subtle.deriveBits({name: 'HKDF', hash: 'SHA-256', salt: nonce, info: info}, k, BLOCK * 8));
    }
    return Promise.all(jobs);
  }).then(function (parts) {
    for (var i = 0; i < parts.length; i++) {
      var s = new Uint8Array(parts[i]), base = i * BLOCK, n = Math.min(BLOCK, cipher.length - base);
      for (var j = 0; j < n; j++) { cipher[base + j] ^= s[j]; }
    }
    var stream = new Blob([cipher]).stream().pipeThrough(new DecompressionStream('gzip'));
    return new Response(stream).text();
  }).then(JSON.parse);
}

function getJSON(path) {
  path = path.replace(/\.json$/, '.bin');
  if (CACHE[path]) { return CACHE[path]; }
  CACHE[path] = fetch(path + '?v=' + encodeURIComponent(META.built)).then(function (r) {
    if (!r.ok) { throw new Error(path); }
    return r.arrayBuffer();
  }).then(decrypt);
  CACHE[path].catch(function () { delete CACHE[path]; });
  return CACHE[path];
}
function loadMeta() {
  return fetch('data/meta.json', {cache: 'no-store'}).then(function (r) { return r.json(); }).then(function (m) { META = m; });
}
function unlock() {     // 保存してある鍵が使えればそのまま。なければ合言葉を聞く
  var saved = null;
  try { saved = localStorage.getItem('kk-key'); } catch (e) {}
  var raw = saved ? unb64(saved) : null;
  return (raw ? checkKey(raw) : Promise.resolve(false)).then(function (ok) {
    if (ok) { KEY = raw; return; }
    return new Promise(function (done) {
      app.innerHTML = "<div class='ch'><h1>合言葉</h1></div><form class='find' id='pass'><input type='password' name='p' autocomplete='current-password' placeholder='合言葉'>"
        + "<button>開く</button></form><p class='hint' id='passmsg'>このスマホで一度入れれば、次からは聞きません。</p>";
      document.getElementById('pass').addEventListener('submit', function (e) {
        e.preventDefault();
        var msg = document.getElementById('passmsg');
        msg.textContent = '確かめています…';
        deriveKey(this.p.value).then(function (key) {
          return checkKey(key).then(function (ok) {
            if (!ok) { msg.textContent = '合言葉が違います。'; return; }
            KEY = key;
            try { localStorage.setItem('kk-key', b64(key)); } catch (err) {}
            done();
          });
        });
      });
    });
  });
}
function loadIndex() {
  return getJSON('data/horses.json').then(function (rows) {
    if (!INDEX) {
      INDEX = rows; BY_ID = {};
      rows.forEach(function (r) { BY_ID[r[0]] = r; });
    }
    return INDEX;
  });
}
// 馬の一覧の列: [ID, 馬名, 性, 世代, 中央の出走数, 勝ち, 最後の出走, いまの格指数, 最高, キャリア平均, 格指数のついた走り, 引退, 主戦場, 最高値のレース]
function loadHorse(id) {
  return getJSON('data/h/' + shard(id) + '.json').then(function (d) { return d[id] || null; });
}
function loadRace(id) {
  return getJSON('data/r/' + shard(id) + '.json').then(function (d) { return d[id] || null; });
}

// お気に入り（このスマホのブラウザに覚える）
function store(key, fallback) { try { var v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; } catch (e) { return fallback; } }
function save(key, value) { try { localStorage.setItem(key, JSON.stringify(value)); } catch (e) {} }
function favs() { return store('favs', []); }
function isFav(id) { return favs().indexOf(id) >= 0; }
function toggleFav(id) {
  var list = favs(), at = list.indexOf(id);
  if (at >= 0) { list.splice(at, 1); } else { list.push(id); }
  save('favs', list);
  return at < 0;
}

function shell(body) {
  app.innerHTML = body + "<p class='upd'>データ: " + esc(META.built.replace('T', ' ')) + ' 時点（結果は ' + esc(META.last_result) + ' まで）</p>';
}

// ---- 馬のキャリア ----
// 走りの列: [日付, レースID, 種類(0中央/1地方/2海外), 場とR, レース名, コース, 着順, 着順の注記, 詳しい情報, 評価]
function rolling(runs) {
  var seen = [], out = [];
  runs.forEach(function (r) {
    if (r[9] != null) { seen.push(r[9]); }
    var top = seen.slice(-6).sort(function (a, b) { return b - a; }).slice(0, 2);
    out.push(top.length ? top.reduce(function (a, b) { return a + b; }, 0) / top.length : null);
  });
  return out;
}

function chart(runs) {
  var points = [];
  runs.forEach(function (r, i) { if (r[9] != null) { points.push([i, r]); } });
  if (!points.length) { return ''; }
  var now = rolling(runs);
  var width = 400, height = 250, left = 26, right = 10, top = 12, bottom = 20;
  var values = points.map(function (p) { return idx(p[1][9]); });
  var low = Math.max(100, Math.min.apply(null, values) - 25), high = Math.min(999, Math.max.apply(null, values) + 25);
  if (high - low < 120) { var mid = (high + low) / 2; low = mid - 60; high = mid + 60; }
  var step = (width - left - right) / runs.length;
  var x = function (i) { return left + step * (i + 0.5); };
  var y = function (v) { return top + (height - top - bottom) * (high - v) / (high - low); };
  var out = ["<svg class='chart' viewBox='0 0 " + width + ' ' + height + "' role='img' aria-label='格指数の推移'>"];
  var upper = high;
  META.ranks.forEach(function (rk) {
    var floor = rk[0], name = rk[1];
    if (upper <= low) { return; }
    var b = Math.max(floor, low);
    if (b < upper) {
      out.push("<rect x='" + left + "' y='" + y(upper).toFixed(1) + "' width='" + (width - left - right) + "' height='" + (y(b) - y(upper)).toFixed(1)
               + "' fill='" + META.rank_colors[name] + "' opacity='.09'/>");
      out.push("<text class='rk' x='3' y='" + ((y(upper) + y(b)) / 2 + 3).toFixed(1) + "' style='fill:" + META.rank_colors[name] + "'>" + name + '</text>');
      if (floor > low) { out.push("<line class='tick' x1='" + left + "' x2='" + (width - right) + "' y1='" + y(floor).toFixed(1) + "' y2='" + y(floor).toFixed(1) + "'/>"); }
    }
    upper = floor;
  });
  var lastYear = null;
  runs.forEach(function (r, i) {
    var year = (r[0] || '').slice(0, 4);
    if (year !== lastYear) {
      var edge = x(i) - step / 2;
      if (i) { out.push("<line class='tick' x1='" + edge.toFixed(1) + "' x2='" + edge.toFixed(1) + "' y1='" + top + "' y2='" + (height - bottom) + "'/>"); }
      out.push("<text x='" + (Math.max(left, edge) + 1).toFixed(1) + "' y='" + (height - 7) + "'>" + year + '</text>');
      lastYear = year;
    }
  });
  out.push("<polyline class='run' points='" + points.map(function (p) { return x(p[0]).toFixed(1) + ',' + y(idx(p[1][9])).toFixed(1); }).join(' ') + "'/>");
  var line = [];
  now.forEach(function (v, i) { if (v != null) { line.push(x(i).toFixed(1) + ',' + y(idx(v)).toFixed(1)); } });
  out.push("<polyline class='now' points='" + line.join(' ') + "'/>");
  var peak = points[0];
  points.forEach(function (p) { if (p[1][9] > peak[1][9]) { peak = p; } });
  points.forEach(function (p) {
    var i = p[0], r = p[1], v = idx(r[9]), px = x(i), py = y(v), win = r[6] === 1;
    out.push("<g data-run='" + i + "'><title>" + esc(r[0] + ' ' + r[4] + ' ' + (r[6] || '-') + '着 格指数 ' + v) + '</title>'
             + (win ? "<circle class='out' cx='" + px.toFixed(1) + "' cy='" + py.toFixed(1) + "' r='6'/>" : '')
             + "<circle cx='" + px.toFixed(1) + "' cy='" + py.toFixed(1) + "' r='" + (win ? 4 : 3) + "' fill='" + META.rank_colors[rankOf(v)] + "'/>"
             + "<circle cx='" + px.toFixed(1) + "' cy='" + py.toFixed(1) + "' r='10' fill='transparent'/></g>");
    if (p === peak) {
      var anchor = px > width - 40 ? 'end' : px < left + 30 ? 'start' : 'middle';
      out.push("<text class='val' x='" + px.toFixed(1) + "' y='" + Math.max(py - 9, 10).toFixed(1) + "' text-anchor='" + anchor + "'>" + v + '</text>');
    }
  });
  out.push('</svg>');
  return out.join('');
}

function radar(grades) {
  var n = META.axes.length, c = 110, rr = 78;
  var point = function (i, k) { var a = -Math.PI / 2 + 2 * Math.PI * i / n; return [c + rr * k * Math.cos(a), c + rr * k * Math.sin(a)]; };
  var xy = function (p) { return p[0].toFixed(1) + ',' + p[1].toFixed(1); };
  var out = ["<svg viewBox='-18 0 256 220' class='radar' role='img' aria-label='能力のレーダー図'>"];
  [0.25, 0.5, 0.75, 1].forEach(function (k) {
    var pts = []; for (var i = 0; i < n; i++) { pts.push(xy(point(i, k))); }
    out.push("<polygon points='" + pts.join(' ') + "' class='ring'/>");
  });
  for (var i = 0; i < n; i++) { var e = point(i, 1); out.push("<line x1='" + c + "' y1='" + c + "' x2='" + e[0].toFixed(1) + "' y2='" + e[1].toFixed(1) + "' class='ring'/>"); }
  var shape = grades.map(function (g, i) {
    var v = g == null ? 0.35 : 1 - META.grades.indexOf(g) / META.grades.length;
    return xy(point(i, Math.max(0.08, v)));
  });
  out.push("<polygon points='" + shape.join(' ') + "' class='shape'/>");
  META.axes.forEach(function (a, i) {
    var p = point(i, 1.2);
    out.push("<text x='" + p[0].toFixed(1) + "' y='" + (p[1] + 4).toFixed(1) + "' text-anchor='middle'>" + esc(a[1]) + '</text>');
  });
  out.push('</svg>');
  return out.join('');
}

function gradeBadge(g) { return g == null ? "<span class='g none'>－</span>" : "<span class='g g-" + g[0] + "'>" + g + '</span>'; }

function abilityPanel(ab) {
  if (!ab || !ab[0]) { return ''; }
  var pane = function (p, key, label) {
    var ranks = META.axes.map(function (a, i) { return "<div title='" + esc(a[2]) + "'><span>" + esc(a[1]) + '</span>' + gradeBadge(p[2][i]) + '</div>'; }).join('');
    return "<div class='abp abp-" + key + "'><p class='hint'>" + label + ': ' + esc(p[0]) + ' ' + esc(p[1]) + (p[3] ? ' を走ったあと（いま）' : ' に出走した時点') + '</p>'
           + radar(p[2]) + "<div class='ab'>" + ranks + '</div></div>';
  };
  var both = !!ab[1];
  return "<div class='abwrap' data-v='" + (both ? (store('career-ab', 'recent') === 'peak' ? 'peak' : 'recent') : 'recent') + "'><div class='yr'>能力値</div>"
         + (both ? "<div class='views' id='abv'><button data-v='recent'>近走</button><button data-v='peak'>全盛期</button></div>" : '')
         + pane(ab[0], 'recent', '近走') + (both ? pane(ab[1], 'peak', '全盛期') : '')
         + "<p class='hint'>ランクは全レース共通の物差しです（カードは同じクラスの中で比べるので、ランクが違うことがあります）。"
         + '全盛期は、スピード・末脚・先行力・粘り・安定感のランクの合計がいちばん高かった時点です。距離適性は、そのレースの距離に対するものです。</p></div>';
}

function runRow(i, r) {
  var finish = r[6], mark = finish ? String(finish) : (r[7] || '－');
  var title = r[1] ? "<a href='#/race/" + esc(r[1]) + "'>" + esc(r[4]) + '</a>' : esc(r[4]);
  var head = [md(r[0]), r[3]].filter(Boolean).join(' ') + (r[2] === 2 ? ' 格指数は推定（出馬表の JRA のレーティングから）' : '');
  var info = [r[5], r[8]].filter(Boolean).join(' ・ ');
  var style = finish >= 1 && finish <= 3 ? ' f' + finish : '';
  return "<div class='cr' id='run" + i + "'><span class='fin" + style + "'>" + esc(mark) + '</span>'
         + "<div class='mid'><small>" + esc(head) + '</small>' + title + '<small>' + esc(info) + '</small></div>'
         + (r[2] === 0 || r[9] != null ? badge(idx(r[9])) : '') + '</div>';
}

function oldOf(h) {     // 世代の順位の1行（h）の古馬換算。年齢は、最後に走った年 − 生まれた年（世代 − 3）
  return h[6] ? oldEquiv(h[7], parseInt(h[6].slice(0, 4), 10) - (h[3] - 3), parseInt(h[6].slice(5, 7), 10)) : h[7];
}
function roadMatch(road, want) {     // career.road_match と同じ。「両方」の馬は、どちらで絞っても出す
  return !want || road === '両方' || road === (want === '芝' ? '芝' : 'ダート');
}
function generationTable(gen) {
  return INDEX.filter(function (h) { return h[3] === gen && h[7] != null && !foreign(h[0]); })
              .sort(function (a, b) { return b[7] - a[7]; });
}

function renderHorse(id) {
  return Promise.all([loadHorse(id), loadIndex()]).then(function (res) {
    var h = res[0];
    if (!h) { shell("<div class='note'>この馬の記録はありません。</div>"); return; }
    var runs = h.r, central = runs.filter(function (r) { return r[2] === 0; });
    var last = central[central.length - 1];
    var now = idx(rolling(runs)[runs.length - 1]);
    var rated = runs.filter(function (r) { return r[9] != null; });
    var peak = null; rated.forEach(function (r) { if (!peak || r[9] > peak[9]) { peak = r; } });
    var counts = [1, 2, 3].map(function (k) { return central.filter(function (r) { return r[6] === k; }).length; });
    var away = runs.filter(function (r) { return r[2] === 2; }).length;
    var others = central.length - counts[0] - counts[1] - counts[2];
    var place = null, table = null;
    if (h.g && now) {
      table = generationTable(h.g);
      for (var k = 0; k < table.length; k++) { if (table[k][0] === id) { place = k + 1; break; } }
    }
    var tierName = h.f ? '外国馬' : h.tr[1];
    var body = ["<div class='ch " + esc(h.tr[0]) + "'><span class='tier'>" + esc(tierName) + '</span><h1>' + esc(h.n) + '</h1><small>' + esc(h.s || '') + (h.a || '')
      + (last[0].slice(0, 4) !== String(new Date().getFullYear()) ? '（最後の出走時）' : '')
      + (h.ret ? ' ・ ' + esc(h.ret.replace(/-/g, '/')) + ' 引退' : '')
      + (h.t ? ' ・ ' + esc(h.t) : '')
      + (h.g ? " ・ <a style='color:inherit' href='#/?gen=" + h.g + "'>" + (h.g % 100) + '世代</a>' : '')
      + (h.rd ? ' ・ 主戦場 ' + esc(h.rd) : '') + '</small></div>'];
    if (h.pd) {     // 血統（career.pedigree_line と同じ）
      body.push("<p class='ped'><b>父</b>" + esc(h.pd[0]) + '　<b>母</b>' + esc(h.pd[1] || '―') + (h.pd[2] ? '（<b>母の父</b>' + esc(h.pd[2]) + '）' : '') + '</p>');
    }
    var label = confidence(rated.length);
    var stats = ['<div>' + badge(now) + '<small>いまの格指数' + (label ? '（<b>' + label + '</b>）' : '') + '</small></div>'];
    var old = oldEquiv(now, h.a, parseInt(last[0].slice(5, 7), 10));
    if (old !== now) { stats.push('<div>' + badge(old) + '<small>古馬換算（目安）</small></div>'); }
    if (peak) { stats.push('<div>' + badge(idx(peak[9])) + '<small>最高: ' + esc(peak[4]) + '（' + esc(peak[0].slice(0, 7).replace('-', '/')) + '）</small></div>'); }
    if (rated.length >= 2) {
      var avg = rated.reduce(function (a, r) { return a + r[9]; }, 0) / rated.length;
      stats.push('<div>' + badge(idx(avg)) + '<small>キャリア平均（' + rated.length + '走）</small></div>');
    }
    if (h.f) { stats.push('<div><small>外国から遠征してきた馬です。日本で走ったレースの分だけで、世代の順位には入れていません。</small></div>'); }
    if (place) { stats.push('<div><b>' + place + "位</b><small><a href='#/?gen=" + h.g + "'>" + (h.g % 100) + '世代の中で</a>（' + table.length + '頭）</small></div>'); }
    var nar = runs.length - central.length - away;
    stats.push('<div><b>' + counts.join('-') + '-' + others + '</b><small>中央 ' + central.length + '戦' + (nar ? ' ・ 地方 ' + nar + '戦' : '') + (away ? ' ・ 海外 ' + away + '戦' : '') + '</small></div>');
    body.push("<div class='cs'>" + stats.join('') + '</div>');
    var on = isFav(id);
    body.push("<div class='fav'><button type='button' id='favbtn' class='" + (on ? 'on' : '') + "'>" + (on ? '★ お気に入り（外す）' : '☆ お気に入りに入れる') + '</button></div>');
    body.push(chart(runs));
    body.push("<p class='lg'>点 = 1走ごとの格指数（◎は勝ったレース。押すと下のそのレースへ）<i></i>その時点の格指数（直近6走の良い2走）</p>");
    if (h.a === 2) { body.push("<p class='hint'>" + esc(META.growth_note) + '</p>'); }
    body.push(abilityPanel(h.ab));
    var year = null;
    for (var i = runs.length - 1; i >= 0; i--) {
      var y = (runs[i][0] || '').slice(0, 4);
      if (y !== year) { body.push("<div class='yr'>" + y + '年</div>'); year = y; }
      body.push(runRow(i, runs[i]));
    }
    body.push("<p class='hint'>格指数は、一緒に走った馬のその後の成績でも動きます（データを作り直すたびに変わります）。"
      + '2021年8月〜2025年のレースは名前の記録がないので、クラスで出しています。海外と地方の交流重賞の格指数は、JRA のレーティングからの推定です。</p>');
    shell(body.join(''));
    document.title = h.n + ' - 格指数';
    var btn = document.getElementById('favbtn');
    btn.addEventListener('click', function () {
      var added = toggleFav(id);
      btn.className = added ? 'on' : '';
      btn.textContent = added ? '★ お気に入り（外す）' : '☆ お気に入りに入れる';
    });
    var abv = document.getElementById('abv');
    if (abv) {
      var set = function (v) {
        abv.parentNode.dataset.v = v;
        Array.prototype.forEach.call(abv.querySelectorAll('button'), function (b) { b.classList.toggle('on', b.dataset.v === v); });
        save('career-ab', v);
      };
      set(abv.parentNode.dataset.v);
      abv.addEventListener('click', function (e) { if (e.target.dataset.v) { set(e.target.dataset.v); } });
    }
  });
}

// ---- レース結果 ----
function renderRace(id) {
  return loadRace(id).then(function (race) {
    if (!race) { shell("<div class='note'>このレースの記録はありません。</div>"); return; }
    var h = race.h, rows = race.e;
    var body = ["<div class='ch'><h1>" + esc(h[4]) + (h[5] ? '（' + esc(h[5]) + '）' : '') + '</h1><small>' + esc(h[0]) + ' ' + esc(h[1]) + h[2] + 'R ・ '
                + esc(h[3]) + ' ・ ' + rows.length + '頭</small></div>'];
    if (!rows.some(function (r) { return r[0]; })) { body.push("<div class='note'>結果はまだ入っていません。</div>"); }
    rows.forEach(function (r) {
      var finish = r[0], style = finish >= 1 && finish <= 3 ? ' f' + finish : '';
      var link = r[2] ? "<a href='#/horse/" + esc(r[2]) + "'>" + esc(r[3]) + '</a>' : esc(r[3]);
      body.push("<div class='cr'><span class='fin" + style + "'>" + esc(finish ? String(finish) : (r[1] || '－')) + '</span>'
                + "<div class='mid'>" + link + '<small>' + esc(r[4]) + '</small></div>' + badge(idx(r[5])) + '</div>');
    });
    body.push("<p class='hint'>右の数字は、この走りの格指数（レース後の評価）です。一緒に走った馬のその後の成績でも動きます。障害レースには出ません。</p>");
    shell(body.join(''));
    document.title = h[4] + ' - 格指数';
  });
}

// ---- 馬を探す・世代の順位 ----
function renderHorses(params) {
  return loadIndex().then(function () {
    var word = (params.q || '').trim();
    var def = currentGeneration(), gen = parseInt(params.gen, 10) || def;
    var sex = params.sex || '', sort = ['peak', 'avg', 'old'].indexOf(params.sort) >= 0 ? params.sort : 'now';
    var road = params.road === '芝' || params.road === 'ダ' ? params.road : '';
    var body = ["<div class='ch'><h1>馬を探す</h1></div>",
                "<form class='find' id='find'><input name='q' value='" + esc(word) + "' placeholder='馬名（一部でも）' enterkeyhint='search'><button>探す</button></form>"];
    if (word) {
      var hits = INDEX.filter(function (h) { return h[1] && h[1].indexOf(word) >= 0; })
                      .sort(function (a, b) { return (b[6] || '').localeCompare(a[6] || ''); }).slice(0, 50);
      body.push(hits.length ? "<div class='yr'>「" + esc(word) + '」の検索結果 ' + hits.length + '頭</div>' : "<div class='note'>見つかりませんでした。</div>");
      hits.forEach(function (h) {
        body.push("<div class='rankrow'><div class='mid'><a href='#/horse/" + esc(h[0]) + "'>" + esc(h[1]) + '</a>'
                  + '<small>' + esc(h[2] || '') + ' ・ ' + h[4] + '戦' + h[5] + '勝 ・ 最後の出走 ' + esc(h[6] || '') + '</small></div>' + badge(h[7]) + '</div>');
      });
      body.push("<p class='hint'><a href='#/'>世代の順位を見る</a></p>");
    } else {
      var link = function (g, s, o, w) {
        if (w === undefined) { w = road; }
        var q = ['gen=' + g]; if (s) { q.push('sex=' + encodeURIComponent(s)); } if (w) { q.push('road=' + encodeURIComponent(w)); } if (o !== 'now') { q.push('sort=' + o); }
        return '#/?' + q.join('&');
      };
      var chips = [];
      for (var g = def; g > def - 8; g--) { chips.push("<a class='" + (g === gen ? 'on' : '') + "' href='" + link(g, sex, sort) + "'>" + (g % 100) + '世代</a>'); }
      body.push("<div class='yr'>世代の順位</div><div class='gens'>" + chips.join('') + '</div>');
      body.push("<div class='gens'>"
        + [['', '全部'], ['牝', '牝馬']].map(function (s) { return "<a class='" + (s[0] === sex ? 'on' : '') + "' href='" + link(gen, s[0], sort) + "'>" + s[1] + '</a>'; }).join('')
        + "</div><div class='gens'>"
        + [['', '芝・ダート'], ['芝', '芝'], ['ダ', 'ダート']].map(function (w) { return "<a class='" + (w[0] === road ? 'on' : '') + "' href='" + link(gen, sex, sort, w[0]) + "'>" + w[1] + '</a>'; }).join('')
        + [['now', 'いまの格指数順'], ['old', '古馬換算順'], ['peak', '最高値順'], ['avg', 'キャリア平均順']].map(function (o) {
            return "<a class='" + (o[0] === sort ? 'on' : '') + "' href='" + link(gen, sex, o[0]) + "'>" + o[1] + '</a>';
          }).join('') + '</div>');
      var picked = generationTable(gen).filter(function (h) { return (!sex || h[2] === sex) && roadMatch(h[12], road); });
      if (sort === 'peak') { picked = picked.slice().sort(function (a, b) { return b[8] - a[8]; }); }
      if (sort === 'old') { picked = picked.slice().sort(function (a, b) { return oldOf(b) - oldOf(a); }); }
      if (sort === 'avg') { picked = picked.filter(function (h) { return h[10] >= AVG_MIN_RUNS; }).sort(function (a, b) { return b[9] - a[9]; }); }
      // 説明が長くなったので、最初の1文のほかは折りたたむ（career.render_horses と同じ）
      body.push("<p class='hint'>" + (gen % 100) + '世代 = ' + (gen - 3) + '年生まれ（' + gen + '年がクラシックの年）。' + picked.length + '頭のうち上位100頭。</p>'
        + "<details class='more'><summary>数字の見方</summary><p>"
        + (gen === currentGeneration() && new Date().getMonth() + 1 >= 6 ? esc(META.growth_note) : '')
        + (road ? esc(META.road_note || '') : '') + esc(META.confidence_note || '')
        + (picked.slice(0, 100).some(function (h) { return oldOf(h) !== h[7]; }) ? esc(META.old_note || '') : '')
        + (sort === 'avg' ? 'キャリア平均は、格指数のついた全部の走りの平均（' + AVG_MIN_RUNS + '走以上の馬だけ）。大敗も入るので、いつも安定して走った馬が上に来ます。' : '') + '</p></details>');
      picked.slice(0, 100).forEach(function (h, k) {
        body.push("<div class='rankrow'><span class='no'>" + (k + 1) + "</span><div class='mid'><a href='#/horse/" + esc(h[0]) + "'>" + esc(h[1]) + '</a>'
          + '<small>' + (h[12] ? esc(h[12]) + ' ・ ' : '') + esc(h[2] || '') + ' ・ ' + h[4] + '戦' + h[5] + '勝' + (confidence(h[10]) ? ' ・ <b>' + confidence(h[10]) + '</b>' : '') + ' ・ 最後の出走 ' + esc(h[6] || '')
          + (oldOf(h) !== h[7] && sort !== 'old' ? ' ・ 古馬換算 約' + oldOf(h) : '') + (sort === 'peak' && h[13] ? ' ・ 最高: ' + esc(h[13]) : '') + '</small></div>'
          + (sort === 'peak' ? "<span class='pk'>いま " + h[7] + '</span>' + badge(h[8]) + '</div>'
             : sort === 'old' ? "<span class='pk'>いま " + h[7] + '</span>' + badge(oldOf(h)) + '</div>'
             : sort === 'avg' ? "<span class='pk'>最高 " + h[8] + '<br>いま ' + h[7] + '</span>' + badge(h[9]) + '</div>'
             : "<span class='pk'>最高 " + h[8] + '</span>' + badge(h[7]) + '</div>'));
      });
      if (!picked.length) { body.push("<div class='note'>この世代の記録はまだありません。</div>"); }
    }
    shell(body.join(''));
    document.title = '馬を探す - 格指数';
    document.getElementById('find').addEventListener('submit', function (e) {
      e.preventDefault();
      var q = this.q.value.trim();
      location.hash = q ? '#/?q=' + encodeURIComponent(q) : '#/';
    });
  });
}

// ---- お気に入り ----
function spark(runs, now) {
  var points = [];
  runs.forEach(function (r, i) { if (r[9] != null) { points.push([i, idx(r[9])]); } });
  points = points.slice(-12);
  if (points.length < 2) { return "<span class='spark'></span>"; }
  var width = 110, height = 30;
  var values = points.map(function (p) { return p[1]; });
  points.forEach(function (p) { if (now[p[0]] != null) { values.push(idx(now[p[0]])); } });
  var low = Math.min.apply(null, values) - 8, high = Math.max.apply(null, values) + 8;
  if (high - low < 80) { var mid = (high + low) / 2; low = mid - 40; high = mid + 40; }
  var x = function (k) { return 4 + (width - 8) * k / (points.length - 1); };
  var y = function (v) { return 3 + (height - 6) * (high - v) / (high - low); };
  var out = ["<svg class='spark' viewBox='0 0 " + width + ' ' + height + "' role='img' aria-label='格指数の推移'>",
             "<polyline class='run' points='" + points.map(function (p, k) { return x(k).toFixed(1) + ',' + y(p[1]).toFixed(1); }).join(' ') + "'/>"];
  var line = [];
  points.forEach(function (p, k) { if (now[p[0]] != null) { line.push(x(k).toFixed(1) + ',' + y(idx(now[p[0]])).toFixed(1)); } });
  out.push("<polyline class='now' points='" + line.join(' ') + "'/>");
  points.forEach(function (p, k) { out.push("<circle cx='" + x(k).toFixed(1) + "' cy='" + y(p[1]).toFixed(1) + "' r='2' fill='" + META.rank_colors[rankOf(p[1])] + "'/>"); });
  out.push('</svg>');
  return out.join('');
}

function renderFavorites(params) {
  var ids = favs();
  if (!ids.length) {
    shell("<div class='ch'><h1>お気に入りの馬</h1></div><div class='note'>まだ登録がありません。馬のキャリアページの「☆ お気に入りに入れる」で登録できます。"
          + 'お気に入りは、このスマホのブラウザに覚えます。</div>');
    return Promise.resolve();
  }
  return loadIndex().then(function () {
    var page = Math.max(1, parseInt(params.page, 10) || 1);
    var rows = ids.map(function (id) { return BY_ID[id]; }).filter(Boolean)
                  .sort(function (a, b) { return (a[11] - b[11]) || (b[6] || '').localeCompare(a[6] || ''); });
    var pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
    page = Math.min(page, pages);
    var shown = rows.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
    var wanted = page === 1 ? rows : shown;     // 今後の出走は1ページ目に、全部のお気に入りの分を出す
    return Promise.all(wanted.map(function (h) { return loadHorse(h[0]); })).then(function (list) {
      var horses = {};
      wanted.forEach(function (h, i) { horses[h[0]] = list[i]; });
      var day = today(), stamp = new Date();
      var seen = store('fav-seen', {});
      var body = ["<div class='ch'><h1>お気に入りの馬</h1></div>"];
      if (page === 1) {
        var upcoming = [];
        rows.forEach(function (h) {
          var d = horses[h[0]];
          if (!d) { return; }
          d.r.forEach(function (r) { if (r[2] === 0 && r[6] == null && !r[7] && r[0] >= day) { upcoming.push([h, r]); } });
        });
        upcoming.sort(function (a, b) { return a[1][0].localeCompare(b[1][0]); });
        if (upcoming.length) {
          body.push("<div class='yr'>今後の出走（データを作った時点の出馬表から）</div>");
          upcoming.forEach(function (u) {
            var r = u[1];
            body.push("<div class='rankrow'><div class='mid'><a href='#/horse/" + esc(u[0][0]) + "'>★ " + esc(u[0][1]) + '</a>'
                      + '<small>' + esc(md(r[0]) + ' ' + r[3] + ' ' + r[4] + ' ' + r[5]) + " ・ <a href='#/race/" + esc(r[1]) + "'>出走馬を見る</a></small></div></div>");
          });
        }
      }
      var active = [], gone = [], fresh = 0;
      shown.forEach(function (h) {
        var d = horses[h[0]];
        if (!d) { return; }
        var runs = d.r.filter(function (r) { return r[6] != null || r[7] || r[0] < day; });
        var now = rolling(runs), last = runs[runs.length - 1];
        // NEW: 前回このページを見たあとに、新しい出走の結果が入った馬（3日のあいだ出す）
        var s = seen[h[0]] || {};
        if (last) {
          if (!s.run) { s.run = last[0]; } else if (last[0] > s.run) { s.run = last[0]; s.since = stamp.toISOString(); }
          seen[h[0]] = s;
        }
        var isNew = s.since && (stamp - new Date(s.since)) < NEW_DAYS * 86400000;
        if (isNew) { fresh++; }
        var lines = [esc((d.s || '') + ' ・ ' + h[4] + '戦' + h[5] + '勝' + (h[9] != null ? ' ・ キャリア平均 ' + h[9] + ' ・ 最高 ' + h[8] : ''))];
        if (last) {
          var text = '前走 ' + (last[0].slice(0, 4) !== day.slice(0, 4) ? last[0].slice(0, 4) + '/' : '') + md(last[0]) + ' ' + last[4] + ' ' + (last[6] ? last[6] + '着' : '－');
          if (last[9] != null) { text += ' ・ その走り ' + idx(last[9]); }
          if (now.length >= 2 && now[now.length - 1] != null && now[now.length - 2] != null) {
            var diff = idx(now[now.length - 1]) - idx(now[now.length - 2]);
            text += ' ・ 格指数 ' + (diff > 0 ? '↑' : diff < 0 ? '↓' : '→') + (diff ? Math.abs(diff) : '');
          }
          lines.push(esc(text));
        }
        if (d.ret) { lines.push(esc(d.ret.replace(/-/g, '/')) + ' 引退（JRA の登録抹消）'); }
        var row = "<div class='rankrow" + (d.ret ? ' retired' : '') + "'><div class='mid'><a href='#/horse/" + esc(h[0]) + "'>" + esc(h[1]) + '</a>'
                  + (isNew ? "<span class='newtag'>NEW</span>" : '') + lines.map(function (x) { return '<small>' + x + '</small>'; }).join('')
                  + '</div>' + spark(runs, now) + badge(h[7]) + '</div>';
        (d.ret ? gone : active).push(row);
      });
      save('fav-seen', seen);
      var retiredAll = rows.filter(function (h) { return h[11]; }).length;
      body.push("<div class='yr'>現役 " + (rows.length - retiredAll) + '頭' + (retiredAll ? ' ・ 引退 ' + retiredAll + '頭' : '') + (fresh ? ' ・ 新しい結果 ' + fresh + '頭' : '')
                + (pages > 1 ? '（' + page + ' / ' + pages + 'ページ）' : '') + '</div>');
      body.push(active.join(''));
      if (gone.length) { body.push("<div class='yr'>引退</div>" + gone.join('')); }
      if (pages > 1) {
        var links = [];
        for (var p = 1; p <= pages; p++) { links.push("<a class='" + (p === page ? 'on' : '') + "' href='#/fav?page=" + p + "'>" + p + '</a>'); }
        body.push("<div class='gens'>" + links.join('') + '</div>');
      }
      body.push("<p class='hint'>右の小さなグラフは直近12走の格指数（点は1走ごと、青い線はその時点の格指数）。「格指数 ↑15」は、前走でいまの格指数がどれだけ動いたか。"
                + 'NEW は、前回このページを見たあとに結果が入った馬（' + NEW_DAYS + '日のあいだ出します）。お気に入りは、このスマホのブラウザに覚えます（ほかの人には見えません）。'
                + 'ブラウザのデータを消すと、お気に入りも消えます。</p>');
      shell(body.join(''));
      document.title = 'お気に入り - 格指数';
    });
  });
}

// ---- 画面の切り替え ----
function parse() {
  var hash = location.hash.replace(/^#\/?/, '');
  var at = hash.indexOf('?'), path = at >= 0 ? hash.slice(0, at) : hash, params = {};
  if (at >= 0) {
    hash.slice(at + 1).split('&').forEach(function (kv) {
      var p = kv.split('='); if (p[0]) { params[decodeURIComponent(p[0])] = decodeURIComponent(p[1] || ''); }
    });
  }
  return {parts: path.split('/').filter(Boolean), params: params};
}

function route() {
  var r = parse(), name = r.parts[0] || '', job;
  Array.prototype.forEach.call(document.querySelectorAll('[data-nav]'), function (a) {
    a.classList.toggle('on', (a.dataset.nav === 'fav') === (name === 'fav'));
  });
  app.innerHTML = "<div class='loading'>読み込んでいます…</div>";
  if (name === 'horse' && r.parts[1]) { job = renderHorse(r.parts[1]); }
  else if (name === 'race' && r.parts[1]) { job = renderRace(r.parts[1]); }
  else if (name === 'fav') { job = renderFavorites(r.params); }
  else { job = renderHorses(r.params); }
  job.then(function () { window.scrollTo(0, 0); }, function (e) {
    app.innerHTML = "<div class='note'>データを読み込めませんでした。電波の良いところで、もう一度開いてください。（" + esc(e && e.message) + '）</div>';
  });
}

// グラフの点を押すと、下の一覧のその走りへ
document.addEventListener('click', function (e) {
  var g = e.target.closest && e.target.closest('[data-run]');
  if (!g) { return; }
  var row = document.getElementById('run' + g.getAttribute('data-run'));
  if (row) {
    row.scrollIntoView({behavior: 'smooth', block: 'center'});
    row.style.outline = '2px solid var(--hit)';
    setTimeout(function () { row.style.outline = ''; }, 1500);
  }
});

loadMeta().then(unlock).then(function () {
  window.addEventListener('hashchange', route);     // 合言葉を確かめてから、画面の切り替えを受け付ける
  route();
}, function () {
  app.innerHTML = "<div class='note'>データを読み込めませんでした。電波の良いところで、もう一度開いてください。</div>";
});
})();
