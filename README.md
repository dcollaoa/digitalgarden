# dcollao Digital Garden 🌱

Welcome to the dcollao Digital Garden, a curated collection of notes, ideas, and resources. This project uses a combination of tools and customizations to provide a seamless and visually appealing experience. Below you'll find a detailed description of the project's contents and setup.

## Project Content

### Obsidian Markdowns
- **Obsidian** is used to create and manage markdown notes.

### Mkdocs Material
- **Mkdocs** is a static site generator that's great for project documentation. We're using the **Material for Mkdocs** theme to provide a clean, responsive design.

### Highlight.js
- **Highlight.js** is integrated to provide syntax highlighting for code blocks. This makes code snippets more readable and visually appealing.

### Personalized Theme (3ky.css)
- Custom styles are defined in **3ky.css** to personalize the appearance of the site. This ensures the garden has a unique look that reflects the brand.

### Google Analytics
- **Google Analytics** is included to track visitor interactions and gather insights on content performance.

### Extra CSS/JS
- Additional CSS and JavaScript files are used to enhance the functionality and appearance of the site. These files are included as needed to provide custom features and styles.

### Personal Banner
- A **personal banner** is displayed at the top of the site. This banner is a visual representation of the contact info and provides a welcoming introduction to visitors.

## Installation and Setup

To set up on your local machine, follow these steps:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/dcollao-digital-garden.git
   cd dcollao-digital-garden
   ```

2. **Install Mkdocs and the Material theme:**
   ```bash
   python3 -m venv venv
   pip install mkdocs-material
   pip install mkdocs-glightbox
   npm install highlight.js
   cd venv
   mkdocs new .
   mkdocs serve
   ```
   The site will be available at `http://127.0.0.1:8000`.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests to enhance the content.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.
