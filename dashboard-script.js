// ===== DASHBOARD SCRIPT SANS DONNÉES FACTICES =====
// Version propre sans données factices ni fonctionnalités de commande

document.addEventListener('DOMContentLoaded', function() {
    console.log('📊 Tableau de Bord initialisé (version propre)');
    
    // Vérification de connexion
    checkLoginStatus();
    
    // Initialisation
    initializeDashboard();
    setupEventListeners();
    updateDateTime();
    
    // Vérifier si c'est la première visite
    checkFirstVisit();
});

// ===== VARIABLES =====
let stats = {
    commandes: 0,
    rupture: 0,
    articles: 0,
    stock: 0
};

// ===== FONCTIONS D'INITIALISATION =====
function initializeDashboard() {
    console.log('Initialisation du tableau de bord...');
    
    // Mettre à jour les informations utilisateur
    updateUserInfo();
    
    // Mettre à jour les statistiques
    updateStatsDisplay();
    
    // Mettre à jour le badge des notifications
    updateNotificationBadge();
    
    console.log('✅ Tableau de bord initialisé');
}

function setupEventListeners() {
    console.log('Configuration des événements...');
    
    // Navigation menu
    document.querySelectorAll('.menu-item').forEach(item => {
        item.addEventListener('click', function(e) {
            if (this.href && this.href.includes('#')) {
                e.preventDefault();
                const pageName = this.querySelector('span').textContent;
                showPageNotAvailable(pageName);
            }
        });
    });
    
    // Bouton de notification
    const notificationBtn = document.getElementById('notification-btn');
    if (notificationBtn) {
        notificationBtn.addEventListener('click', showNoNotifications);
    }
    
    // Boutons d'actions rapides
    const addArticleBtn = document.getElementById('add-article-btn');
    if (addArticleBtn) {
        addArticleBtn.addEventListener('click', showAddArticleModal);
    }
    
    const addCategoryBtn = document.getElementById('add-category-btn');
    if (addCategoryBtn) {
        addCategoryBtn.addEventListener('click', showAddCategoryModal);
    }
    
    const addServiceBtn = document.getElementById('add-service-btn');
    if (addServiceBtn) {
        addServiceBtn.addEventListener('click', showAddServiceModal);
    }
    
    const configBtn = document.getElementById('config-btn');
    if (configBtn) {
        configBtn.addEventListener('click', showConfigModal);
    }
    
    // Bouton "Voir Toutes"
    const viewAllBtn = document.getElementById('view-all-btn');
    if (viewAllBtn) {
        viewAllBtn.addEventListener('click', function(e) {
            if (this.disabled) {
                e.preventDefault();
                showSystemNotConfigured();
            }
        });
    }
    
    // Bouton de déconnexion
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', handleLogout);
    }
    
    // Modal de configuration
    const closeConfigBtn = document.getElementById('close-config-btn');
    if (closeConfigBtn) {
        closeConfigBtn.addEventListener('click', closeConfigModal);
    }
    
    const cancelConfigBtn = document.getElementById('cancel-config-btn');
    if (cancelConfigBtn) {
        cancelConfigBtn.addEventListener('click', closeConfigModal);
    }
    
    const saveConfigBtn = document.getElementById('save-config-btn');
    if (saveConfigBtn) {
        saveConfigBtn.addEventListener('click', saveConfiguration);
    }
    
    // Options de configuration
    document.querySelectorAll('.config-option').forEach(option => {
        option.addEventListener('click', function() {
            const optionId = this.id;
            handleConfigOption(optionId);
        });
    });
    
    // Fermer la modal en cliquant à l'extérieur
    const configModal = document.getElementById('config-modal');
    if (configModal) {
        configModal.addEventListener('click', function(e) {
            if (e.target === this) {
                closeConfigModal();
            }
        });
    }
    
    console.log('✅ Événements configurés');
}

// ===== FONCTIONS D'AFFICHAGE =====
function updateStatsDisplay() {
    // Toutes les statistiques sont à 0
    document.querySelectorAll('.stat-value').forEach(element => {
        element.textContent = '0';
    });
}

function updateNotificationBadge() {
    const badge = document.querySelector('.notification-badge');
    if (badge) {
        badge.textContent = '0';
        badge.style.background = '#6c757d';
    }
}

function updateDateTime() {
    const dateElement = document.getElementById('current-date');
    if (!dateElement) return;
    
    const now = new Date();
    const options = { 
        weekday: 'long', 
        year: 'numeric', 
        month: 'long', 
        day: 'numeric' 
    };
    
    dateElement.textContent = now.toLocaleDateString('fr-FR', options);
    
    // Mettre à jour chaque minute
    setTimeout(updateDateTime, 60000);
}

// ===== GESTION UTILISATEUR =====
function checkLoginStatus() {
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    
    if (!user || !user.name) {
        // Rediriger vers la page de connexion
        setTimeout(() => {
            window.location.href = 'login.html';
        }, 100);
        return false;
    }
    
    return true;
}

function updateUserInfo() {
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    
    const userName = document.getElementById('user-name');
    const userRole = document.getElementById('user-role');
    const logoutBtn = document.getElementById('logout-btn');
    
    if (user && user.name) {
        // Mettre à jour le nom
        if (userName) {
            userName.textContent = user.name;
        }
        
        // Mettre à jour le rôle
        if (userRole) {
            userRole.textContent = user.role === 'admin' ? 'Administrateur' : 'Utilisateur';
            userRole.style.color = user.role === 'admin' ? '#4cc9f0' : '#adb5bd';
        }
        
        // Mettre à jour le bouton de déconnexion
        if (logoutBtn) {
            logoutBtn.innerHTML = `
                <i class="fas fa-sign-out-alt"></i>
                <span>Déconnexion</span>
            `;
        }
    }
}

function handleLogout(e) {
    e.preventDefault();
    
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    
    if (user && user.name) {
        if (confirm(`Voulez-vous vous déconnecter, ${user.name}?`)) {
            // Effacer les données locales
            localStorage.removeItem('user');
            localStorage.removeItem('last_login');
            localStorage.removeItem('session_start');
            localStorage.removeItem('csrf_token');
            
            // Rediriger vers la page de connexion
            showLoading('Déconnexion en cours...');
            setTimeout(() => {
                hideLoading();
                window.location.href = 'login.html';
            }, 1000);
        }
    } else {
        // Si non connecté, rediriger vers la page de connexion
        window.location.href = 'login.html';
    }
}

// ===== FONCTIONS DE MODAL =====
function showConfigModal() {
    const modal = document.getElementById('config-modal');
    if (modal) {
        modal.style.display = 'flex';
    }
}

function closeConfigModal() {
    const modal = document.getElementById('config-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

function handleConfigOption(optionId) {
    const messages = {
        'config-articles': 'Configuration des articles - Fonctionnalité à implémenter',
        'config-categories': 'Configuration des catégories - Fonctionnalité à implémenter',
        'config-services': 'Configuration des services - Fonctionnalité à implémenter',
        'config-users': 'Gestion des utilisateurs - Fonctionnalité à implémenter'
    };
    
    if (messages[optionId]) {
        alert(messages[optionId]);
    }
}

function saveConfiguration() {
    showLoading('Enregistrement de la configuration...');
    
    // Simuler l'enregistrement
    setTimeout(() => {
        hideLoading();
        closeConfigModal();
        alert('✅ Configuration enregistrée avec succès!\n\nLes modifications seront effectives après redémarrage.');
    }, 1500);
}

// ===== FONCTIONS D'AJOUT =====
function showAddArticleModal() {
    const modal = document.getElementById('config-modal');
    const modalTitle = modal.querySelector('.modal-title');
    const modalBody = modal.querySelector('.modal-body');
    
    modalTitle.innerHTML = `
        <i class="fas fa-box"></i>
        Ajouter un Article
    `;
    
    modalBody.innerHTML = `
        <div class="form-container">
            <h3 style="margin-bottom: 20px; color: #212529;">Ajouter un nouvel article</h3>
            
            <div class="form-group">
                <label for="article-name">Nom de l'article</label>
                <input type="text" id="article-name" class="form-input" 
                       placeholder="Ex: Cahier 96 pages">
            </div>
            
            <div class="form-group">
                <label for="article-category">Catégorie</label>
                <select id="article-category" class="form-input">
                    <option value="">Sélectionner une catégorie</option>
                    <option value="fournitures">Fournitures</option>
                    <option value="informatique">Informatique</option>
                    <option value="entretien">Produits d'entretien</option>
                </select>
            </div>
            
            <div class="form-group">
                <label for="article-quantity">Quantité initiale</label>
                <input type="number" id="article-quantity" class="form-input" 
                       value="1" min="1">
            </div>
            
            <div class="form-group">
                <label for="article-min">Stock minimum</label>
                <input type="number" id="article-min" class="form-input" 
                       value="5" min="1">
            </div>
        </div>
    `;
    
    modal.style.display = 'flex';
}

function showAddCategoryModal() {
    alert('Ajout de catégorie - Fonctionnalité à implémenter\n\nCette fonctionnalité sera disponible dans la prochaine mise à jour.');
}

function showAddServiceModal() {
    alert('Ajout de service - Fonctionnalité à implémenter\n\nCette fonctionnalité sera disponible dans la prochaine mise à jour.');
}

// ===== FONCTIONS UTILITAIRES =====
function showPageNotAvailable(pageName) {
    alert(`Page "${pageName}" non disponible\n\nCette page est en cours de développement et sera disponible prochainement.`);
}

function showNoNotifications() {
    alert('🔔 Aucune notification\n\nVous n\'avez aucune notification pour le moment.');
}

function showSystemNotConfigured() {
    alert('⚙️ Système non configuré\n\nVeuillez configurer le système avant d\'utiliser cette fonctionnalité.\n\nCliquez sur "Configuration" pour commencer.');
}

function checkFirstVisit() {
    const hasVisited = localStorage.getItem('has_visited_dashboard');
    
    if (!hasVisited) {
        // Première visite - Montrer un message d'accueil
        setTimeout(() => {
            alert('👋 Bienvenue dans le système de gestion de stock!\n\nLe système est actuellement vide. Commencez par configurer les articles, catégories et services.');
            localStorage.setItem('has_visited_dashboard', 'true');
        }, 2000);
    }
}

// ===== FONCTIONS DE CHARGEMENT =====
function showLoading(message = 'Chargement...') {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        overlay.querySelector('p').textContent = message;
        overlay.style.display = 'flex';
    }
}

function hideLoading() {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        overlay.style.display = 'none';
    }
}

// ===== GESTION DES ERREURS =====
window.addEventListener('error', function(e) {
    console.error('Erreur JavaScript:', e.error);
    alert('Une erreur s\'est produite. Veuillez réessayer.');
});

// ===== EXPORT DES FONCTIONS (pour la console) =====
window.dashboard = {
    initialize: initializeDashboard,
    updateStats: updateStatsDisplay,
    showConfig: showConfigModal,
    logout: handleLogout
};

console.log('✅ Script du tableau de bord chargé avec succès!');