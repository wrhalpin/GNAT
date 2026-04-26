# Phase 5: Polish & Visual Enhancements

## TUI Visual Polish

### Color Coding
- **Analyst input**: Blue (bold header)
- **Copilot responses**: Red (conversational)
- **Assistant responses**: Yellow (suggestions)
- **System messages**: Dim yellow (status updates)
- **Suggestions**: Green borders (assistant panel)

### Keybindings

**Copilot (F10):**
| Keybinding | Action |
|------------|--------|
| `Escape` | Close copilot |
| `Ctrl+C` | Cancel ongoing LLM stream |
| `F1` | Show help |

**Assistant (F11):**
| Keybinding | Action |
|------------|--------|
| `Escape` | Close assistant |
| `Ctrl+C` | Cancel ongoing request |
| `F1` | Show help |

### Screen Formatting

**Copilot Screen:**
- Heavy borders around status bar, conversation, and input
- Status bar shows phase, IOC count, avg confidence
- Conversation history with color-coded roles
- Input field with contextual placeholder

**Assistant Screen:**
- Header with visual separator (dock: top)
- Response area with colored suggestion panels (green borders)
- Input field with command hints (dock: bottom)
- F1 help shows all available commands and examples

### Stream Cancellation

- `Ctrl+C` while copilot is streaming sets `cancel_stream` flag
- Analyst sees immediate "[System] Stream cancelled" message
- Input field becomes responsive again

### Help System

- F1 opens inline help with:
  - All available slash commands with descriptions
  - Keybindings reference
  - Examples for common workflows

---

## Web UI Polish

### Export Functionality

**Endpoints:**

1. **GET `/api/chat/investigations/{inv_id}/export`**
   - Query params: `conversation_id`, `format` (json|csv)
   - Returns conversation as downloadable JSON or CSV
   - Includes timestamp, role, text, token counts, latency
   - Filename: `conversation_{id}_{timestamp}.{ext}`

2. **POST `/api/chat/investigations/{inv_id}/copy`**
   - Copy suggestion text (ready for browser Clipboard API)
   - Used by Web UI for copy-to-clipboard buttons
   - Returns text in format ready for pasting

3. **GET `/api/chat/investigations/{inv_id}/summary`**
   - Conversation stats: turn count, tokens, latency, duration
   - Agent type breakdown (analyst vs agent messages)
   - Quick reference for conversation metrics

### Web UI Responsive Design

CSS classes ready for responsive implementation:
- Mobile-first approach for analyst on-call scenarios
- Flexible layout adapts to screen size
- Touch-friendly input areas (larger hit targets)
- Collapsible suggestion panels for small screens

### Copy-to-Clipboard Integration

**For suggestions:**
```javascript
// Web UI implementation (example)
async function copySuggestion(text) {
  try {
    await navigator.clipboard.writeText(text);
    showNotification("Copied to clipboard");
  } catch (err) {
    console.error('Failed to copy:', err);
  }
}
```

### Conversation Export

**Download options:**
- JSON export: Full turn data with metadata
- CSV export: Tabular format for spreadsheet analysis
- Both include: timestamp, role, text, tokens, latency
- Filename includes conversation ID and timestamp

---

## Impact on UX

### For Analysts

1. **Faster Visual Parsing**
   - Color-coded messages make it easy to scan conversation flow
   - Suggested actions stand out with green borders
   - System status is visually distinct (dim yellow)

2. **Stream Control**
   - Can cancel long-running copilot queries with Ctrl+C
   - Immediate feedback ("Stream cancelled")
   - Input becomes responsive right away

3. **Quick Help**
   - F1 brings up all available commands
   - Reduces need to check documentation
   - Examples included for common tasks

4. **Export & Review**
   - Export conversations for compliance/post-mortems
   - JSON for detailed analysis, CSV for spreadsheet review
   - Summary stats help understand investigation cost/duration

### For On-Call Analysts

1. **Mobile-Friendly Web UI**
   - Responsive layout adapts to phone/tablet
   - Larger touch targets for mobile input
   - Copy suggestions to paste into other tools

2. **Quick Copy**
   - One-click copy of copilot suggestions
   - Copy enrichment connector names to run queries
   - Paste recommendations into incident chat/tickets

---

## Files Modified

### TUI
- `gnat/tui/screens/copilot_screen.py`
  - Added color constants and color-coded message methods
  - Added CSS with borders and layout
  - Added F1 help action
  - Added Ctrl+C stream cancellation
  - Updated placeholder text with keybinding hints

- `gnat/tui/screens/assistant_screen.py`
  - Added color constants and color-coded message methods
  - Added CSS with docking and borders
  - Added F1 help action
  - Added Ctrl+C cancellation
  - Added suggestion panel coloring (green borders)

### Web API
- `gnat/serve/routers/chat.py`
  - Added `/export` endpoint for JSON/CSV export
  - Added `/copy` endpoint for copy-to-clipboard integration
  - Added `/summary` endpoint for conversation stats
  - Added imports for FileResponse, datetime, csv, StringIO

---

## Testing Checklist

- [ ] Copilot colors render correctly (blue/red/yellow)
- [ ] Ctrl+C cancels stream in copilot
- [ ] F1 shows help in both copilot and assistant
- [ ] Escape closes both screens
- [ ] Export endpoint returns valid JSON
- [ ] Export endpoint returns valid CSV
- [ ] Summary endpoint calculates stats correctly
- [ ] Copy endpoint integrates with browser Clipboard API
- [ ] Assistant suggestion panels have green borders
- [ ] Input placeholders show keybinding hints

---

## Future Enhancements

1. **PDF Export**
   - Render conversation as formatted PDF
   - Include conversation summary on cover page
   - Syntax highlighting for code suggestions

2. **Conversation Search**
   - Full-text search within conversation history
   - Filter by role (analyst/copilot/assistant)
   - Filter by date range

3. **Conversation Sharing**
   - Generate shareable links (read-only)
   - Expire after N days
   - Redact sensitive information option

4. **Themes**
   - Light/dark theme toggle
   - Custom color schemes
   - Accessibility theme (high contrast)
