class ThemeManager {
    constructor() {
        this.toggle = document.getElementById('theme-toggle');
        if (!this.toggle) return;

        this.icon = document.getElementById('theme-icon');
        const { iconBase, iconDark, iconLight, soundSrc } = this.toggle.dataset;
        this.iconBase = iconBase;
        this.iconDark = iconDark;
        this.iconLight = iconLight;

        // Create audio element lazily only when needed
        this.sound = null;
        this.soundSrc = soundSrc;

        this.init();
    }

    init() {
        this.setInitialTheme();
        this.toggle.addEventListener('click', () => this.toggleTheme());
    }

    setInitialTheme() {
        const savedTheme = localStorage.getItem('theme');
        const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        const initialTheme = savedTheme || (systemDark ? 'dark' : 'light');

        document.documentElement.setAttribute('data-theme', initialTheme);
        this.updateHighlightTheme(initialTheme === 'dark');
        this.updateIcon(initialTheme === 'dark');
    }

    toggleTheme() {
        document.body.classList.add('theme-transition');
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        const newTheme = isDark ? 'light' : 'dark';

        document.documentElement.setAttribute('data-theme', newTheme);
        this.updateHighlightTheme(newTheme === 'dark');
        this.updateIcon(!isDark);
        renderMermaid();
        localStorage.setItem('theme', newTheme);

        // Lazy load sound only when needed
        if (!this.sound && this.soundSrc) {
            this.sound = new Audio(this.soundSrc);
        }

        if (this.sound) {
            this.sound.play().catch(() => {});
        }

        // Use requestAnimationFrame for better performance on transition
        requestAnimationFrame(() => {
            setTimeout(() => {
                document.body.classList.remove('theme-transition');
            }, 300);
        });
    }

    updateIcon(isDark) {
        if (this.icon) {
            this.icon.setAttribute('href',
                `${this.iconBase}${isDark ? this.iconDark : this.iconLight}`);
        }
    }

    updateHighlightTheme(isDark) {
        const lightTheme = document.getElementById('giallo-light');
        const darkTheme = document.getElementById('giallo-dark');

        if (lightTheme && darkTheme) {
            lightTheme.disabled = isDark;
            darkTheme.disabled = !isDark;
        }
    }
}

function renderMath() {
    if (typeof renderMathInElement !== 'function') return;

    const content = document.querySelector('main');
    if (!content) return;

    renderMathInElement(content, {
        delimiters: [
            { left: '$$', right: '$$', display: true },
            { left: '\\[', right: '\\]', display: true },
            { left: '\\(', right: '\\)', display: false },
            { left: '$', right: '$', display: false }
        ],
        ignoredTags: ['script', 'noscript', 'style', 'textarea', 'pre', 'code'],
        throwOnError: false,
        strict: false,
        trust: false
    });
}

function isMermaidCodeBlock(code) {
    const language = code.dataset.lang || '';
    return language.toLowerCase() === 'mermaid' || code.classList.contains('language-mermaid');
}

let mermaidRenderSequence = 0;

async function renderMermaid() {
    if (typeof mermaid === 'undefined') return;

    const content = document.querySelector('main');
    if (!content) return;

    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    mermaid.initialize({
        startOnLoad: false,
        securityLevel: 'strict',
        theme: isDark ? 'dark' : 'default'
    });

    const codeBlocks = [...content.querySelectorAll('pre code')]
        .filter(isMermaidCodeBlock);
    const diagrams = [...content.querySelectorAll('.mermaid-diagram')];

    for (const code of codeBlocks) {
        const source = code.textContent.trim();
        const diagram = document.createElement('div');
        diagram.className = 'mermaid-diagram';
        diagram.dataset.mermaidSource = source;
        code.closest('pre').replaceWith(diagram);
        diagrams.push(diagram);
    }

    for (const diagram of diagrams) {
        const source = diagram.dataset.mermaidSource;
        if (!source) continue;

        try {
            const { svg, bindFunctions } = await mermaid.render(`mermaid-diagram-${mermaidRenderSequence++}`, source);
            diagram.innerHTML = svg;
            bindFunctions?.(diagram);
        } catch (error) {
            diagram.classList.add('mermaid-error');
            diagram.textContent = 'Mermaid diagram could not be rendered.';
            console.warn('Mermaid rendering failed:', error);
        }
    }
}


// Initialize when content is loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new ThemeManager();
        renderMath();
        renderMermaid();
    });
} else {
    new ThemeManager();
    renderMath();
    renderMermaid();
}
