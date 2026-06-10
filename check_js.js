// Extract and validate the script block from index.html
const fs = require('fs');
const content = fs.readFileSync('index.html', 'utf8');
const start = content.indexOf('<script>') + 8;
const end = content.lastIndexOf('</script>');
const script = content.slice(start, end);

console.log('Script length:', script.length);

// Try to parse it
try {
  new Function(script);
  console.log('✓ JavaScript valide — aucune erreur de syntaxe');
} catch(e) {
  console.log('✗ ERREUR JS:', e.message);
  // Find approximate line number
  const lines = script.split('\n');
  const match = e.message.match(/line (\d+)/i);
  if (match) {
    const lineNo = parseInt(match[1]);
    console.log('Contexte:');
    for (let i = Math.max(0, lineNo-3); i < Math.min(lines.length, lineNo+2); i++) {
      console.log(`  ${i+1}: ${lines[i]}`);
    }
  }
}
