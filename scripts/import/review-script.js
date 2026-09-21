const records = DATA.candidates;
const container = document.querySelector('#records');
const status = document.querySelector('#status');
const download = document.querySelector('#download');
const controls = [];
let dirty = false;
function element(tag, text) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  return node;
}
function update() {
  const count = controls.filter(item => item.check.checked).length;
  status.textContent = `${count} of ${records.length} selected`;
  download.disabled = count === 0;
}
for (const [index, record] of records.entries()) {
  const card = element('article');
  const label = element('label');
  const check = element('input');
  check.type = 'checkbox';
  check.checked = record.selected === true;
  check.addEventListener('change', update);
  label.append(check, document.createTextNode(` Include quote ${(record.original_ids || [index + 1]).join(' + ')}`));
  const source = element('p', `${record.source_timestamp} · source line ${record.source_line} · ${record.count} occurrence(s)`);
  source.className = 'source';
  card.append(label, source);
  if (record.needs_review) {
    const warning = element('p', `Check carefully: ${record.reason || 'ambiguous formatting'}`);
    warning.className = 'warning';
    card.append(warning);
  }
  const evidence = record.evidence_text || record.surrounding_text;
  if (evidence) {
    const details = element('details');
    const excerpt = element('p', evidence);
    excerpt.style.whiteSpace = 'pre-wrap';
    details.append(element('summary', 'Source message and nearby context'), excerpt);
    card.append(details);
  }
  const quoteLabel = element('label', 'Quote or conversation');
  const quote = element('textarea');
  quote.rows = Math.min(10, Math.max(3, record.text.split('\n').length + 1));
  quote.value = record.text;
  quoteLabel.append(quote);
  const authorLabel = element('label', 'People quoted (not necessarily the sender)');
  const author = element('input');
  author.type = 'text';
  author.value = record.author;
  authorLabel.append(author);
  const contextLabel = element('label', 'Context (optional; correct or remove any suggestion)');
  const context = element('textarea');
  context.rows = 2;
  context.value = record.context || '';
  context.className = 'context';
  contextLabel.append(context);
  if (record.context_note) card.append(element('p', record.context_note));
  const senderLabel = element('label', 'Originally shared by');
  const sender = element('input');
  sender.type = 'text';
  sender.className = 'source-sender';
  sender.value = record.source_sender || '';
  senderLabel.append(sender);
  card.append(quoteLabel, authorLabel, senderLabel, contextLabel);
  card.addEventListener('input', () => {dirty = true;});
  container.append(card);
  controls.push({check, quote, author, context, sender, record});
}
function values(items) {
  return items.map(({check, quote, author, context, sender, record}) => ({
    text: quote.value, author: author.value, context: context.value, source_sender: sender.value, selected: check.checked,
    original_ids: record.original_ids || [],
    source: {type: 'apple-messages-export', timestamp: record.source_timestamp,
      line: record.source_line, message_line: record.source_message_line, occurrences: record.count, sender: record.source_sender,
      id: record.source_id, chat: record.source_chat, attribution_message_line: record.attribution_message_line,
      corrections: record.corrections || []}
  }));
}
function save(value, filename) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], {type: 'application/json'}));
  const link = element('a');
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
download.addEventListener('click', () => {
  const selected = controls.filter(item => item.check.checked);
  for (const item of selected) {
    if (!item.quote.value.trim() || !item.author.value.trim()) {
      status.textContent = 'Every selected quote needs text and a person. Please correct the highlighted field.';
      (!item.quote.value.trim() ? item.quote : item.author).focus();
      return;
    }
  }
  const quotes = values(selected).map(({selected, ...quote}) => ({...quote,
    text: quote.text.trim(), author: quote.author.trim(), context: quote.context.trim(), source_sender: quote.source_sender.trim()}));
  save({format: 'quotevault-reviewed-quotes', version: 1, quotes}, 'quotevault-reviewed-quotes.json');
});
document.querySelector('#draft').addEventListener('click', () => {
  save({format: 'quotevault-review-draft', version: 1, source_fingerprint: DATA.source_fingerprint,
    quotes: values(controls)}, 'quotevault-review-draft.json');
});
document.querySelector('#restore').addEventListener('change', async event => {
  try {
    const file = event.target.files[0];
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) throw new Error('Draft is too large.');
    const draft = JSON.parse(await file.text());
    if (draft.format !== 'quotevault-review-draft' || draft.version !== 1 ||
        draft.source_fingerprint !== DATA.source_fingerprint ||
        !Array.isArray(draft.quotes) || draft.quotes.length !== controls.length) {
      throw new Error('This draft does not belong to this review.');
    }
    for (const [index, row] of draft.quotes.entries()) {
      if (!row || ['text', 'author', 'context'].some(key => typeof row[key] !== 'string') ||
          typeof row.selected !== 'boolean' || (row.source_sender !== undefined && typeof row.source_sender !== 'string') || row.source?.line !== records[index].source_line ||
          JSON.stringify(row.original_ids) !== JSON.stringify(records[index].original_ids || [])) {
        throw new Error('Draft has invalid or mismatched entries. No changes applied.');
      }
    }
    if (dirty && !confirm('Replace current unsaved edits with this saved draft?')) return;
    draft.quotes.forEach((row, index) => {
      const item = controls[index];
      item.quote.value = row.text; item.author.value = row.author;
      item.context.value = row.context; item.check.checked = row.selected;
      if (row.source_sender !== undefined) item.sender.value = row.source_sender;
    });
    dirty = true;
    update();
  } catch (error) { status.textContent = error.message; }
  finally { event.target.value = ''; }
});
window.addEventListener('beforeunload', event => {
  if (dirty) {event.preventDefault(); event.returnValue = '';}
});
update();
