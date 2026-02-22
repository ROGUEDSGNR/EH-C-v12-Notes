# GitBook Setup and Usage Guide

This repository is now configured to work with GitBook, making it easy to create beautiful, searchable documentation from these study notes.

## 📚 What is GitBook?

GitBook is a modern documentation platform that transforms your markdown files into a professional, searchable documentation website. It's perfect for creating course materials, technical documentation, and study guides.

## 🚀 Publishing to GitBook

### Option 1: GitBook Cloud (Recommended)

1. **Sign up for GitBook**
   - Go to [https://www.gitbook.com](https://www.gitbook.com)
   - Create a free account or sign in with GitHub

2. **Import this Repository**
   - Click "New Space" in GitBook
   - Select "Import from GitHub"
   - Choose this repository (`ROGUEDSGNR/EH-C-v12-Notes`)
   - GitBook will automatically detect the `.gitbook.yaml` configuration

3. **Publish**
   - GitBook will automatically build your documentation
   - You'll get a live URL to share your GitBook
   - Any updates pushed to GitHub will automatically sync

### Option 2: Local Preview with GitBook CLI

You can also preview the GitBook locally before publishing:

1. **Install GitBook CLI**
   ```bash
   npm install -g gitbook-cli
   ```

2. **Install Dependencies**
   ```bash
   cd /path/to/EH-C-v12-Notes
   gitbook install
   ```

3. **Serve Locally**
   ```bash
   gitbook serve
   ```
   
   This will start a local server at `http://localhost:4000`

4. **Build Static Site**
   ```bash
   gitbook build
   ```
   
   This creates a `_book` directory with static HTML files

## 📁 GitBook File Structure

The GitBook configuration uses these key files:

- **`.gitbook.yaml`** - Configuration file that tells GitBook where to find content
- **`SUMMARY.md`** - Table of contents and navigation structure
- **`README.md`** - Introduction/landing page
- **Module files** (e.g., `01-Introduction-to-Ethical-Hacking.md`) - Content pages
- **`Images/`** - Image assets referenced in the documentation
- **`Labs/`** - Practical lab exercises

## 🎨 Customization Options

### Updating Navigation

To modify the table of contents, edit `SUMMARY.md`. The structure follows this format:

```markdown
* [Page Title](path/to/file.md)
  * [Subpage Title](path/to/subpage.md)
```

### Adding New Pages

1. Create a new markdown file in the appropriate location
2. Add an entry in `SUMMARY.md` to include it in navigation
3. Use standard markdown syntax for content

### Customizing Appearance

GitBook supports various customization options:
- Themes and colors (configure in GitBook dashboard)
- Custom domain names (paid plans)
- Logo and branding (in GitBook settings)

## 📝 Markdown Best Practices for GitBook

### Links
- Use relative paths: `[Link Text](./other-page.md)`
- Cross-reference sections: `[Section](#section-title)`

### Images
- Use standard markdown: `![Alt Text](Images/image.png)`
- Images are automatically optimized by GitBook

### Code Blocks
```python
# Use language-specific syntax highlighting
def example():
    return "Hello World"
```

### Callouts and Hints
GitBook supports special callouts:

{% hint style="info" %}
This is an info callout
{% endhint %}

{% hint style="warning" %}
This is a warning callout
{% endhint %}

## 🔄 Keeping GitBook Updated

When you push changes to GitHub:
1. Update or add markdown files
2. Update `SUMMARY.md` if adding new pages
3. Commit and push changes
4. GitBook will automatically rebuild (if using GitBook Cloud)

## 🌐 Sharing Your GitBook

Once published, you can:
- Share the public URL with students
- Embed GitBook pages in other sites
- Export to PDF (paid plans)
- Enable/disable public access

## 🆚 GitBook vs Obsidian

This repository can be used with both:
- **GitBook**: For publishing and sharing online
- **Obsidian**: For personal note-taking and study

The markdown files are compatible with both platforms!

## 📖 Additional Resources

- [GitBook Documentation](https://docs.gitbook.com)
- [Markdown Guide](https://www.markdownguide.org)
- [GitBook Community](https://github.com/GitbookIO)

## ⚡ Quick Start Summary

1. Sign up at [gitbook.com](https://www.gitbook.com)
2. Import this GitHub repository
3. GitBook automatically builds your documentation
4. Share the generated URL with your audience

That's it! Your ethical hacking study notes are now a professional documentation site.
