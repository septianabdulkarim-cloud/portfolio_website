/* =========================
   Toggle Navbar
========================= */
const toggleBtn = document.getElementById('navbar-toggle');
const navMenu = document.querySelector('.navbar-nav');

toggleBtn.addEventListener('click', () => {
    navMenu.classList.toggle('open');
});

/* =========================
   About Image Toggle Text
========================= */
const aboutImg = document.getElementById('about-img');
const aboutText = document.getElementById('about-text');

aboutImg.addEventListener('click', () => {
    aboutText.classList.toggle('hidden');
});

// Klik di luar gambar & teks untuk sembunyikan teks
document.addEventListener('click', (e) => {
    if (
        !aboutImg.contains(e.target) &&
        !aboutText.contains(e.target) &&
        !aboutText.classList.contains('hidden')
    ) {
        aboutText.classList.add('hidden');
    }
});

/* =========================
   Animasi Saat Scroll
========================= */
function isInViewport(element) {
    const rect = element.getBoundingClientRect();
    return rect.top <= (window.innerHeight || document.documentElement.clientHeight) * 0.85;
}

function checkAnimation() {
    const sections = document.querySelectorAll('#alasan-mahal .container');
    sections.forEach(section => {
        if (isInViewport(section)) {
            section.classList.add('visible');
        }
    });
}

window.addEventListener('scroll', checkAnimation);
window.addEventListener('load', checkAnimation);

/* =========================
   Ganti Gambar di Projects
========================= */
document.querySelectorAll('#projects .project-card img').forEach((img, index, images) => {
    img.style.cursor = 'pointer';

    img.addEventListener('click', () => {
        const nextIndex = (index + 1) % images.length;

        // Simpan gambar sekarang
        const currentSrc = img.src;
        const currentAlt = img.alt;

        // Ambil gambar berikutnya
        const nextImg = images[nextIndex];

        // Tukar posisi gambar
        img.src = nextImg.src;
        img.alt = nextImg.alt;
        nextImg.src = currentSrc;
        nextImg.alt = currentAlt;
    });
});

/* =========================
   Toggle Card Services
========================= */
const cards = document.querySelectorAll('#services .card.project-card');

cards.forEach(card => {
    const img = card.querySelector('img');
    const body = card.querySelector('.card-body');

    img.style.cursor = 'pointer';

    img.addEventListener('click', () => {
        // Tutup semua kartu lain
        cards.forEach(c => {
            if (c !== card) {
                c.querySelector('.card-body').classList.remove('active');
            }
        });

        // Toggle kartu yang diklik
        body.classList.toggle('active');
    });
});

/* =========================
   Testimonial Slider
========================= */
const testimonials = document.querySelectorAll('#testimonials .testimonial');
let current = 0;

function showTestimonial(index) {
    testimonials.forEach((t, i) => {
        t.classList.toggle('active', i === index);
    });
}

// Tampilkan testimonial pertama
showTestimonial(current);

// Ganti testimonial tiap 6 detik
setInterval(() => {
    current = (current + 1) % testimonials.length;
    showTestimonial(current);
}, 6000);
// Fade-in saat scroll
const skills = document.querySelectorAll('.skill-item');

const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
        if(entry.isIntersecting){
            entry.target.classList.add('visible');
        }
    });
}, { threshold: 0.2 });

skills.forEach(skill => observer.observe(skill));



function updateTime() {
  const now = new Date();
  const options = { 
    weekday: 'long', 
    year: 'numeric', 
    month: 'long', 
    day: 'numeric',
    hour: '2-digit', 
    minute: '2-digit', 
    second: '2-digit',
    hour12: false 
  };
  
  document.getElementById("current-time").textContent = 
    now.toLocaleDateString('id-ID', options);
}

setInterval(updateTime, 1000);
updateTime();
