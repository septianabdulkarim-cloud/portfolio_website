<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Dashboard Client - {{ email }}</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet" />
  <link
    rel="stylesheet"
    href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"
    integrity="sha512-pOaXy+H9yrN+03U7aXLFoRgiBxZ+XQaZZQFnz+6VXq3FeSFiZVbLK3FmVy0b95d7/1zoGz8e+QQ0Rl6XMaY5xg=="
    crossorigin="anonymous"
    referrerpolicy="no-referrer"
  />
  <style>
    /* Reset dan style sama seperti sebelumnya */
    * {
      box-sizing: border-box;
    }
    body {
      margin: 0;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen,
        Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
      display: flex;
      min-height: 100vh;
      background: linear-gradient(135deg, #e0e7ff 0%, #f5f7fa 100%);
      color: #333;
      overflow: hidden;
    }
    .sidebar {
      width: 260px;
      background: linear-gradient(180deg, #1e40af, #2563eb);
      color: #e0e7ff;
      display: flex;
      flex-direction: column;
      padding: 2.5rem 1.5rem;
      box-shadow: 4px 0 15px rgba(37, 99, 235, 0.3);
      transition: width 0.35s cubic-bezier(0.4, 0, 0.2, 1);
      user-select: none;
    }
    .sidebar h2 {
      font-weight: 700;
      font-size: 1.8rem;
      text-align: center;
      margin-bottom: 2.5rem;
      letter-spacing: 1.3px;
      color: #bfdbfe;
      text-shadow: 0 0 5px rgba(255 255 255 / 0.2);
    }
    .sidebar button {
      background: transparent;
      border: none;
      color: #dbeafe;
      padding: 16px 22px;
      text-align: left;
      font-size: 1.1rem;
      cursor: pointer;
      border-left: 5px solid transparent;
      margin-bottom: 0.8rem;
      border-radius: 8px;
      transition:
        background-color 0.3s ease,
        border-left-color 0.3s ease,
        color 0.3s ease,
        box-shadow 0.3s ease;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 14px;
      box-shadow: inset 0 0 0 transparent;
    }
    .sidebar button i {
      min-width: 24px;
      font-size: 1.3rem;
      color: inherit;
      transition: color 0.3s ease;
    }
    .sidebar button:hover {
      background-color: rgba(96, 165, 250, 0.15);
      border-left-color: #93c5fd;
      color: #f3f4f6;
      box-shadow: 0 2px 12px rgba(37, 99, 235, 0.5);
    }
    .sidebar button.active {
      background-color: #2563eb;
      border-left-color: #60a5fa;
      color: #fff;
      box-shadow: 0 4px 20px rgba(96, 165, 250, 0.7);
    }
    .content-wrapper {
      flex-grow: 1;
      padding: 2.5rem 3rem;
      overflow-y: auto;
      background: #fff;
      box-shadow:
        inset 0 0 12px #dbeafe,
        0 0 24px rgb(37 99 235 / 0.15);
      display: flex;
      flex-direction: column;
      border-radius: 16px 0 0 16px;
      animation: fadeIn 0.5s ease forwards;
      outline: none;
    }
    .content-wrapper:focus {
      box-shadow:
        0 0 0 3px #2563eb,
        inset 0 0 12px #dbeafe,
        0 0 24px rgb(37 99 235 / 0.3);
    }
    .content-wrapper h1 {
      color: #1e40af;
      margin-top: 0;
      margin-bottom: 1.25rem;
      font-weight: 800;
      font-size: 2.25rem;
      letter-spacing: 0.02em;
      user-select: none;
    }
    .content-wrapper p {
      font-size: 1.1rem;
      line-height: 1.65;
      color: #444;
      user-select: text;
    }
    .file-list {
      margin-top: 2.5rem;
      padding-left: 1rem;
      max-width: 650px;
    }
    .file-list h3 {
      font-weight: 700;
      color: #1e40af;
      margin-bottom: 1.25rem;
      font-size: 1.4rem;
      letter-spacing: 0.01em;
    }
    .file-list ul {
      list-style-type: disc;
      padding-left: 2rem;
      color: #555;
      font-size: 1.05rem;
    }
    .file-list ul li {
      margin-bottom: 0.7rem;
      transition: color 0.3s ease;
    }
    .file-list ul li:hover {
      color: #2563eb;
    }
    .content-wrapper::-webkit-scrollbar {
      width: 10px;
    }
    .content-wrapper::-webkit-scrollbar-track {
      background: #f0f4ff;
      border-radius: 8px;
    }
    .content-wrapper::-webkit-scrollbar-thumb {
      background: #2563eb;
      border-radius: 8px;
    }
    .content-wrapper::-webkit-scrollbar-thumb:hover {
      background: #1e40af;
    }
    @keyframes fadeIn {
      from {
        opacity: 0;
        transform: translateY(12px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }
    .projects-list {
      margin-top: 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 1.8rem;
      max-width: 650px;
    }
    .project-card {
      background: #f3f4f6;
      border-radius: 12px;
      padding: 1.3rem 1.5rem;
      box-shadow: 0 2px 8px rgb(37 99 235 / 0.15);
      transition: box-shadow 0.3s ease;
    }
    .project-card:hover {
      box-shadow: 0 4px 20px rgb(37 99 235 / 0.3);
    }
    .project-card h3 {
      margin: 0 0 0.6rem;
      font-weight: 700;
      color: #1e40af;
    }
    .progress-bar {
      background: #dbeafe;
      border-radius: 9999px;
      height: 14px;
      overflow: hidden;
      margin-bottom: 0.5rem;
    }
    .progress {
      background: #2563eb;
      height: 100%;
      border-radius: 9999px;
      transition: width 0.5s ease;
    }
    .project-card p {
      font-weight: 600;
      color: #444;
    }
    @media (max-width: 768px) {
      body {
        flex-direction: column;
        overflow: auto;
        background: #f5f7fa;
      }
      .sidebar {
        width: 100%;
        flex-direction: row;
        padding: 1rem 0.75rem;
        overflow-x: auto;
        box-shadow: none;
        border-radius: 0;
      }
      .sidebar h2 {
        display: none;
      }
      .sidebar button {
        flex: 1 0 auto;
        text-align: center;
        margin: 0 0.3rem;
        border-left: none;
        border-radius: 12px;
        padding: 10px 14px;
        font-size: 1rem;
        justify-content: center;
        font-weight: 700;
        box-shadow: none;
        transition: box-shadow 0.3s ease;
      }
      .sidebar button i {
        font-size: 1.1rem;
        margin-bottom: 2px;
      }
      .sidebar button.active,
      .sidebar button:hover {
        border-left: none;
        box-shadow: 0 4px 15px rgba(37, 99, 235, 0.6);
        background-color: #2563eb;
        color: #fff;
      }
      .content-wrapper {
        padding: 1.5rem 1.75rem;
        border-radius: 0;
        box-shadow: none;
        flex-grow: unset;
        min-height: 60vh;
      }
      .file-list {
        max-width: 100%;
        margin-top: 1.5rem;
        padding-left: 0;
      }
    }
    form {
      margin-top: 2rem;
      max-width: 650px;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }
    form label {
      font-weight: 600;
      font-size: 1.1rem;
      color: #1e40af;
    }
    form textarea {
      resize: vertical;
      min-height: 80px;
      padding: 0.6rem 0.8rem;
      font-size: 1rem;
      border-radius: 8px;
      border: 1px solid #ccc;
      transition: border-color 0.3s ease;
      font-family: inherit;
    }
    form textarea:focus {
      outline: none;
      border-color: #2563eb;
      box-shadow: 0 0 6px #60a5faaa;
    }
    form button {
      align-self: flex-start;
      padding: 0.6rem 1.2rem;
      font-size: 1rem;
      font-weight: 700;
      color: #fff;
      background-color: #2563eb;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      transition: background-color 0.3s ease;
      user-select: none;
    }
    form button:hover {
      background-color: #1e40af;
    }
  </style>
</head>
<body>
  <nav class="sidebar" role="navigation" aria-label="Sidebar navigation">
    <h2>Dashboard</h2>
    <button class="active" data-section="profile" aria-current="page" onclick="showContent('profile')">
      <i class="fa-solid fa-user"></i> Profil Saya
    </button>
    <button data-section="messages" onclick="showContent('messages')">
      <i class="fa-solid fa-envelope"></i> Pesan
    </button>
    <button data-section="settings" onclick="showContent('settings')">
      <i class="fa-solid fa-gear"></i> Pengaturan
    </button>
    <button data-section="projects" onclick="showContent('projects')">
      <i class="fa-solid fa-diagram-project"></i> Project Anda
    </button>
  </nav>

  <main
    class="content-wrapper"
    id="content-area"
    tabindex="0"
    aria-live="polite"
  >
    <!-- Konten akan dirender oleh JS -->
  </main>

  <script type="application/json" id="data-json">
  {
    "projects": {{ projects|tojson|safe }},
    "email": {{ email|tojson|safe }},
    "clients": {{ clients|tojson|safe }},
    "filesPerClient": {{ files_per_client|tojson|safe }},
    "filesPerProject": {{ files_per_project|tojson|safe }}
  }
  </script>

  <script>
    const dataJsonElement = document.getElementById('data-json');
    const data = JSON.parse(dataJsonElement.textContent);

    const projects = data.projects;
    const email = data.email;
    const clients = data.clients;
    const filesPerClient = data.filesPerClient;
    const filesPerProject = data.filesPerProject;

    const content = document.getElementById('content-area');
    const sidebarButtons = document.querySelectorAll('.sidebar button');

    function renderProfile() {
      let html = `
        <h1>Profil Saya</h1>
        <p>Selamat datang, ${email}! Ini adalah halaman profil Anda.</p>

        <section>
          <div class="uploaded-files file-list">
            <h3>Daftar File yang Sudah Diunggah (Per Client)</h3>
      `;

      if (clients.length > 0) {
        clients.forEach(client => {
          const clientId = String(client.id);
          html += `<div class="client-files"><h4>${client.email}</h4>`;

          if (filesPerClient[clientId] && filesPerClient[clientId].length > 0) {
            html += '<ul>';
            filesPerClient[clientId].forEach(filename => {
              html += `<li>${filename}</li>`;
            });
            html += '</ul>';
          } else {
            html += `<p>Tidak ada file yang diupload.</p>`;
          }
          html += '</div>';
        });
      } else {
        html += `<p>Tidak ada client.</p>`;
      }

      html += `
          </div>
          <div class="uploaded-files file-list" style="margin-top: 2rem;">
            <h3>Daftar File yang Sudah Diunggah (Per Project)</h3>
      `;

      if (Object.keys(filesPerProject).length > 0) {
          for (const [projectName, files] of Object.entries(filesPerProject)) {
            html += `<div class="project-files"><h4>Project: ${projectName}</h4><ul>`;
            files.forEach(file => {
              const downloadUrl = `/download/${encodeURIComponent(file.filename)}`;
              html += `
              <li>
                ${file.filename} 
                <small>(diunggah: ${file.uploaded_at})</small> 
                - <a href="${downloadUrl}" download>Download</a>
              </li>
            `;
            });
            html += '</ul></div>';
          };
      } else {
        html += `<p>Tidak ada file yang diupload untuk project Anda.</p>`;
      }

      html += `
          </div>
        </section>
      `;

      content.innerHTML = html;
    }

    function renderMessages() {
      content.innerHTML = `
        <h1>Pesan</h1>
        <p>Ini adalah halaman pesan Anda. Belum ada pesan baru.</p>

        <form id="message-form" action="{{ url_for('send_client_message') }}" method="post">
          <label for="message">Kirim Pesan ke Admin:</label>
          <textarea name="message" id="message" rows="4" required></textarea>
          <button type="submit">Kirim</button>
        </form>
      `;

      // Event listener submit form kirim pesan
      const form = document.getElementById('message-form');
      form.addEventListener('submit', e => {
        e.preventDefault();

        const message = form.message.value.trim();
        if (!message) {
          alert('Pesan tidak boleh kosong.');
          return;
        }

        // Contoh AJAX submit (fetch)
        fetch(form.action, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message }),
        })
          .then(res => {
            if (res.ok) {
              alert('Pesan berhasil dikirim!');
              form.reset();
            } else {
              alert('Gagal mengirim pesan, coba lagi nanti.');
            }
          })
          .catch(() => alert('Terjadi kesalahan jaringan.'));
      });
    }

    function renderSettings() {
      content.innerHTML = `
        <h1>Pengaturan</h1>
        <p>Atur preferensi dan informasi akun Anda di sini.</p>
      `;
    }

    function renderProjects() {
      let html = `
        <h1>Project Anda</h1>
        <p>Berikut adalah status proyek yang sedang Anda kerjakan:</p>
        <div class="projects-list">
      `;

      if (projects.length > 0) {
        projects.forEach(project => {
          html += `
            <div class="project-card">
              <h3>${project.project_name}</h3>
              <div class="progress-bar">
                <div class="progress" style="width: ${project.progress}%;"></div>
              </div>
              <p>Progress: ${project.progress}%</p>
            </div>
          `;
        });
      } else {
        html += `<p>Anda belum memiliki project.</p>`;
      }

      html += `</div>`;

      content.innerHTML = html;
    }

    function showContent(section) {
      sidebarButtons.forEach(btn => {
        btn.classList.remove('active');
        btn.removeAttribute('aria-current');
      });

      const activeBtn = Array.from(sidebarButtons).find(btn => btn.dataset.section === section);
      if (activeBtn) {
        activeBtn.classList.add('active');
        activeBtn.setAttribute('aria-current', 'page');
      }

      switch (section) {
        case 'profile':
          renderProfile();
          break;
        case 'messages':
          renderMessages();
          break;
        case 'settings':
          renderSettings();
          break;
        case 'projects':
          renderProjects();
          break;
        default:
          renderProfile();
      }

      content.focus();
    }

    sidebarButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        showContent(btn.dataset.section);
      });
    });

    document.addEventListener('DOMContentLoaded', () => {
      showContent('profile');
    });
  </script>
</body>
</html>


