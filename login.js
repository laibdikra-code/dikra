// login.js - النسخة المصححة
document.addEventListener('DOMContentLoaded', function() {

    // 1. تبديل التبويبات
    document.querySelectorAll(".auth-tab").forEach(tab => {
        tab.addEventListener("click", () => {
            document.querySelectorAll(".auth-tab").forEach(t => t.classList.remove("active"));
            tab.classList.add("active");
            document.querySelectorAll(".auth-form").forEach(f => f.classList.remove("active"));
            document.getElementById(tab.dataset.tab + "-form").classList.add("active");
            
            hideAllMessages();
        });
    });

    // 2. إظهار/إخفاء كلمة المرور
    setupPasswordToggle("login-password", "toggle-login-password");
    
    function setupPasswordToggle(passwordId, toggleButtonId) {
        const passwordInput = document.getElementById(passwordId);
        const toggleButton = document.getElementById(toggleButtonId);
        
        if (!passwordInput || !toggleButton) return;
        
        toggleButton.addEventListener("click", () => {
            const type = passwordInput.type === "password" ? "text" : "password";
            passwordInput.type = type;
            toggleButton.innerHTML = type === "password" ? 
                '<i class="fas fa-eye"></i>' : 
                '<i class="fas fa-eye-slash"></i>';
        });
    }

    // 3. وظائف مساعدة
    function showMessage(elementId, message, isError = true) {
        const element = document.getElementById(elementId);
        if (!element) return;
        
        element.textContent = message;
        element.style.display = "block";
        element.className = isError ? "error-message" : "success-message";
        
        if (isError) {
            setTimeout(() => {
                element.style.display = "none";
            }, 5000);
        }
    }

    function hideAllMessages() {
        document.querySelectorAll('.error-message, .success-message').forEach(msg => {
            msg.style.display = 'none';
        });
    }

    // 4. تسجيل الدخول
    document.getElementById("loginBtn").addEventListener("click", async function() {
        const username = document.getElementById("login-username").value.trim();
        const password = document.getElementById("login-password").value.trim();
        
        hideAllMessages();
        
        // التحقق الأساسي
        if (!username || !password) {
            showMessage("login-error", "Veuillez remplir tous les champs");
            return;
        }
        
        const button = this;
        const originalText = button.innerHTML;
        button.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Connexion...`;
        button.disabled = true;
        
        try {
            const response = await fetch('php/auth.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    action: 'login',
                    username: username,
                    password: password
                })
            });
            
            if (!response.ok) {
                throw new Error(`Erreur HTTP: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.success) {
                // حفظ بيانات المستخدم
                localStorage.setItem('user', JSON.stringify(data.user));
                localStorage.setItem('last_login', new Date().toISOString());
                
                // الانتقال بعد تأخير قصير
                setTimeout(() => {
                    window.location.href = data.redirect || 'index.html';
                }, 1000);
                
            } else {
                showMessage("login-error", data.message);
                button.innerHTML = originalText;
                button.disabled = false;
            }
            
        } catch (error) {
            console.error('Login error:', error);
            showMessage("login-error", "Erreur de connexion au serveur");
            button.innerHTML = originalText;
            button.disabled = false;
            
           
        }
    });

    // 5. إضافة إمكانية استخدام Enter
    document.querySelectorAll('.form-input').forEach(input => {
        input.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                document.getElementById('loginBtn').click();
            }
        });
    });
});

// 6. وظيفة تسجيل الخروج
function logout() {
    fetch('php/auth.php', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ action: 'logout' })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            localStorage.clear();
            window.location.href = 'login.html';
        }
    })
    .catch(error => {
        console.error('Logout error:', error);
        localStorage.clear();
        window.location.href = 'login.html';
    });
}