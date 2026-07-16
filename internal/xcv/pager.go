package xcv

import (
	"fmt"
	"os"
	"regexp"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	charmbterm "github.com/charmbracelet/x/term"
)

// ansiRe matches CSI sequences (\x1b[...letter) and two-char escape sequences.
var ansiRe = regexp.MustCompile(`\x1b(?:\[[0-9;?]*[A-Za-z]|[@-Z\\-_])`)

func stripANSI(s string) string {
	return ansiRe.ReplaceAllString(s, "")
}

func isTerminal(f *os.File) bool {
	return charmbterm.IsTerminal(f.Fd())
}

// StdinIsTerminal reports whether stdin is attached to a terminal.
func StdinIsTerminal() bool {
	return isTerminal(os.Stdin)
}

func termWidth() int {
	w, _, err := charmbterm.GetSize(os.Stdout.Fd())
	if err != nil || w <= 0 {
		return 80
	}
	return w
}

type pagerModel struct {
	renderFn func(width int) string
	viewport viewport.Model
	ready    bool
}

func (m pagerModel) Init() tea.Cmd { return nil }

func (m pagerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		if !m.ready {
			m.viewport = viewport.New()
			m.ready = true
		}
		m.viewport.SetWidth(msg.Width)
		m.viewport.SetHeight(msg.Height - 1)
		m.viewport.SetContent(m.renderFn(msg.Width))
	}
	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	return m, cmd
}

func (m pagerModel) View() tea.View {
	if !m.ready {
		v := tea.NewView("")
		v.AltScreen = true
		return v
	}
	pct := int(m.viewport.ScrollPercent() * 100)
	help := lipgloss.NewStyle().Foreground(lipgloss.Color("8")).
		Render(fmt.Sprintf(" ↑/↓  PgUp/PgDn  q quit  %d%%", pct))
	v := tea.NewView(m.viewport.View() + "\n" + help)
	v.AltScreen = true
	return v
}

// pagerKeyInput returns the file the pager should read keystrokes from.
// When stdin carried piped input, keys come from the controlling terminal
// instead. nil means bubbletea's default (stdin).
func pagerKeyInput() (*os.File, error) {
	if isTerminal(os.Stdin) {
		return nil, nil
	}
	return os.Open("/dev/tty")
}

func display(renderFn func(width int) string) {
	if Quiet {
		return
	}
	tty := isTerminal(os.Stdout)
	if tty && !NoColor && !NoPager {
		if in, err := pagerKeyInput(); err == nil {
			var opts []tea.ProgramOption
			if in != nil {
				defer in.Close() //nolint:errcheck // read-only fd
				opts = append(opts, tea.WithInput(in))
			}
			p := tea.NewProgram(pagerModel{renderFn: renderFn}, opts...)
			if _, err := p.Run(); err == nil {
				return
			}
		}
	}
	w := 80
	if tty {
		w = termWidth()
	}
	content := renderFn(w)
	if !tty || NoColor {
		content = stripANSI(content)
	}
	fmt.Print(content)
}
