const WORDS = Object.freeze([
  'abandon','ability','able','about','above','absent','absorb','abstract','absurd','abuse','access','accident','account','accuse','achieve','acid',
  'acoustic','acquire','across','act','action','actor','actress','actual','adapt','add','addict','address','adjust','admit','adult','advance',
  'advice','aerobic','affair','afford','afraid','again','age','agent','agree','ahead','aim','air','airport','aisle','alarm','album','alcohol',
  'alert','alien','all','alley','allow','almost','alone','alpha','already','also','alter','always','amateur','amazing','among','amount','amused',
  'analyst','anchor','ancient','anger','angle','angry','animal','ankle','announce','annual','another','answer','antenna','antique','anxiety','any',
  'apart','apology','appear','apple','approve','april','arch','arctic','area','arena','argue','arm','armed','armor','army','around','arrange',
  'arrest','arrive','arrow','art','artefact','artist','artwork','ask','aspect','assault','asset','assist','assume','asthma','athlete','atom',
  'attack','attend','attitude','attract','auction','audit','august','aunt','author','auto','autumn','average','avocado','avoid','awake','aware',
  'away','awesome','awful','awkward','axis','baby','bachelor','bacon','badge','bag','balance','balcony','ball','bamboo','banana','banner','bar',
  'barely','bargain','barrel','base','basic','basket','battle','beach','bean','beauty','because','become','beef','before','begin','behave','behind',
  'believe','below','belt','bench','benefit','best','betray','better','between','beyond','bicycle','bid','bike','bind','biology','bird','birth',
  'bitter','black','blade','blame','blanket','blast','bleak','bless','blind','blood','blossom','blouse','blue','blur','blush','board','boat',
  'body','boil','bomb','bone','bonus','book','boost','border','boring','borrow','boss','bottom','bounce','box','boy','bracket','brain','brand',
  'brass','brave','bread','breeze','brick','bridge','brief','bright','bring','brisk','broccoli','broken','bronze','broom','brother','brown','brush','bubble','buddy','budget','buffalo','build','bulb','bulk','bullet','bundle','bunker','burden','burger','burst','bus','business','busy','butter','buyer','buzz','xylophone','yellow','zebra'
].map(word => word.trim()));

export const RECOVERY_WORDS = WORDS;

export function generateRecoveryPhrase(): string[] {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  try { return Array.from(bytes, byte => WORDS[byte]); }
  finally { bytes.fill(0); }
}

export function recoveryConfirmationPositions(): number[] {
  const positions: number[] = [];
  while (positions.length < 3) {
    const bytes = crypto.getRandomValues(new Uint8Array(3));
    try {
      for (const byte of bytes) {
        if (byte >= 240) continue;
        const position = byte % 16;
        if (!positions.includes(position)) positions.push(position);
        if (positions.length === 3) break;
      }
    } finally { bytes.fill(0); }
  }
  return positions;
}

export function confirmRecoveryPhrase(words: unknown, answers: unknown, positions: unknown): boolean {
  if (!Array.isArray(words) || words.length !== 16 || words.some(word => typeof word !== 'string' || !WORDS.includes(word))) return false;
  if (!Array.isArray(answers) || !Array.isArray(positions) || answers.length !== 3 || positions.length !== 3) return false;
  if (new Set(positions).size !== 3 || positions.some(position => !Number.isInteger(position) || position < 0 || position >= 16)) return false;
  return positions.every((position, index) => answers[index] === words[position]);
}

/** Typed or pasted phrases may differ in case and whitespace from the saved `words.join(' ')`. */
export function normalizeRecoveryPhrase(phrase: string): string {
  const words = phrase.trim().toLowerCase().split(/\s+/);
  if (words.length !== 16 || words.some(word => !WORDS.includes(word))) throw new Error('Enter all 16 recovery words.');
  return words.join(' ');
}
