// Hamburger Menü Aç/Kapa
const hamburgerMenu = document.getElementById('hamburger-menu');
const navMenu = document.getElementById('nav-menu');

if (hamburgerMenu) {
    hamburgerMenu.addEventListener('click', () => {
        navMenu.classList.toggle('active');
    });
}

// Modal Aç/Kapa
const loginLink = document.getElementById('login-link');
const registerLink = document.getElementById('register-link');
const loginModal = document.getElementById('login-modal');
const registerModal = document.getElementById('register-modal');
const loginClose = document.getElementById('login-close');
const registerClose = document.getElementById('register-close');
const openRegister = document.getElementById('open-register');
const openLogin = document.getElementById('open-login');

// Giriş Modal Açma/Kapatma
if (loginLink) {
    loginLink.addEventListener('click', (e) => {
        e.preventDefault();
        window.location.href = loginLink.href;
    });
}

if (registerLink) {
    registerLink.addEventListener('click', (e) => {
        e.preventDefault();
        window.location.href = registerLink.href;
    });
}

if (loginClose) {
    loginClose.addEventListener('click', () => {
        loginModal.style.display = 'none';
    });
}

if (registerClose) {
    registerClose.addEventListener('click', () => {
        registerModal.style.display = 'none';
    });
}

if (openRegister) {
    openRegister.addEventListener('click', (e) => {
        e.preventDefault();
        loginModal.style.display = 'none';
        registerModal.style.display = 'block';
    });
}

if (openLogin) {
    openLogin.addEventListener('click', (e) => {
        e.preventDefault();
        registerModal.style.display = 'none';
        loginModal.style.display = 'block';
    });
}

// Modal dışında tıklayınca kapat
window.addEventListener('click', (event) => {
    if (event.target === loginModal) {
        loginModal.style.display = 'none';
    }
    if (event.target === registerModal) {
        registerModal.style.display = 'none';
    }
});

// Flash mesajları belirli bir süre sonra otomatik olarak gizle
window.setTimeout(function() {
    $(".bootstrap-alert .alert").fadeTo(500, 0).slideUp(500, function(){
        $(this).remove(); 
    });
}, 5000); // 5 saniye sonra mesajları gizle

$(document).ready(function() {
    // Admin Dropdown
    $('.dropdown-admin').hover(function() {
        $(this).find('.dropdown-menu').stop(true, true).delay(200).fadeIn(200);
    }, function() {
        $(this).find('.dropdown-menu').stop(true, true).delay(200).fadeOut(200);
    });

    // User Dropdown
    $('.dropdown-user').hover(function() {
        $(this).find('.dropdown-menu').stop(true, true).delay(200).fadeIn(200);
    }, function() {
        $(this).find('.dropdown-menu').stop(true, true).delay(200).fadeOut(200);
    });
});




