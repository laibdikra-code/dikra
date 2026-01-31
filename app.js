// app.js - النسخة المصححة
class StockManagementApp {
    constructor() {
        this.currentPage = 1;
        this.ordersPerPage = 10;
        this.allOrders = [];
        this.cartItems = [];
        this.selectedOrder = null;
        this.services = [];
        this.articles = [];
        this.csrfToken = null;
        
        this.initElements();
        this.initEventListeners();
        this.checkAuth();
    }
    
    initElements() {
        this.elements = {
            newOrderBtn: document.getElementById('new-order-btn'),
            addBtn: document.getElementById('add-btn'),
            validateBtn: document.getElementById('validate-btn'),
            prevBtn: document.getElementById('prev-btn'),
            nextBtn: document.getElementById('next-btn'),
            closeModalBtn: document.getElementById('close-modal-btn'),
            printBtn: document.getElementById('print-btn'),
            modalCloseBtn: document.getElementById('close-btn'),
            serviceSelect: document.getElementById('service-select'),
            articleSelect: document.getElementById('article-select'),
            quantityInput: document.getElementById('quantity'),
            commandsBody: document.getElementById('commands-body'),
            cartBody: document.getElementById('cart-body'),
            orderModal: document.getElementById('order-modal'),
            modalBody: document.getElementById('modal-body'),
            paginationInfo: document.getElementById('pagination-info')
        };
    }
    
    initEventListeners() {
        if (this.elements.newOrderBtn) {
            this.elements.newOrderBtn.addEventListener('click', () => this.createOrder());
        }
        
        if (this.elements.addBtn) {
            this.elements.addBtn.addEventListener('click', () => this.addToCart());
        }
        
        if (this.elements.validateBtn) {
            this.elements.validateBtn.addEventListener('click', () => this.validateOrder());
        }
        
        if (this.elements.closeModalBtn) {
            this.elements.closeModalBtn.addEventListener('click', () => this.closeModal());
        }
        
        if (this.elements.articleSelect) {
            this.elements.articleSelect.addEventListener('change', () => this.updateAddButtonState());
        }
        
        if (this.elements.quantityInput) {
            this.elements.quantityInput.addEventListener('input', () => this.updateAddButtonState());
        }
        
        // إضافة Enter لإضافة المواد
        if (this.elements.quantityInput) {
            this.elements.quantityInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter' && !this.elements.addBtn.disabled) {
                    this.addToCart();
                }
            });
        }
    }
    
    async checkAuth() {
        try {
            const response = await fetch('php/auth.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    action: 'check_auth',
                    csrf_token: this.csrfToken
                })
            });
            
            const data = await response.json();
            
            if (!data.authenticated) {
                window.location.href = 'login.html';
                return;
            }
            
            // حفظ CSRF Token
            if (data.csrf_token) {
                this.csrfToken = data.csrf_token;
            }
            
            // تحميل البيانات الأولية
            await this.loadInitialData();
            
        } catch (error) {
            console.error('خطأ في التحقق من المصادقة:', error);
            window.location.href = 'login.html';
        }
    }
    
    async loadInitialData() {
        try {
            // تحميل الخدمات
            const servicesResponse = await fetch('php/api.php?action=getServices');
            const servicesData = await servicesResponse.json();
            
            if (servicesData.success) {
                this.services = servicesData.data;
                this.populateServices();
            }
            
            // تحميل المواد
            const articlesResponse = await fetch('php/api.php?action=getArticles');
            const articlesData = await articlesResponse.json();
            
            if (articlesData.success) {
                this.articles = articlesData.data;
                this.populateArticles();
            }
            
            // تحميل الطلبات
            await this.loadOrders();
            
        } catch (error) {
            console.error('خطأ في تحميل البيانات:', error);
            this.showError('فشل في تحميل البيانات. الرجاء تحديث الصفحة.');
        }
    }
    
    populateServices() {
        if (!this.elements.serviceSelect) return;
        
        this.elements.serviceSelect.innerHTML = '<option value="">اختر الخدمة...</option>';
        
        this.services.forEach(service => {
            const option = document.createElement('option');
            option.value = service.Id_service;
            option.textContent = service.design_ser;
            this.elements.serviceSelect.appendChild(option);
        });
    }
    
    populateArticles() {
        if (!this.elements.articleSelect) return;
        
        this.elements.articleSelect.innerHTML = '<option value="">اختر المادة...</option>';
        
        this.articles.forEach(article => {
            // إظهار فقط المواد المتوفرة في المخزون
            if (article.qte_stock > 0) {
                const option = document.createElement('option');
                option.value = article.id_article;
                option.textContent = `${article.design_art} (المخزون: ${article.qte_stock})`;
                option.dataset.stock = article.qte_stock;
                this.elements.articleSelect.appendChild(option);
            }
        });
        
        this.elements.articleSelect.disabled = false;
        this.elements.quantityInput.disabled = false;
    }
    
    updateAddButtonState() {
        const articleId = this.elements.articleSelect.value;
        const quantity = parseInt(this.elements.quantityInput.value) || 0;
        const selectedArticle = this.articles.find(a => a.id_article == articleId);
        
        if (articleId && quantity > 0 && selectedArticle) {
            // التحقق من أن الكمية لا تتجاوز المخزون
            if (quantity <= selectedArticle.qte_stock) {
                this.elements.addBtn.disabled = false;
                this.elements.quantityInput.classList.remove('error');
            } else {
                this.elements.addBtn.disabled = true;
                this.elements.quantityInput.classList.add('error');
                this.showError(`الكمية المطلوبة (${quantity}) تتجاوز المخزون المتاح (${selectedArticle.qte_stock})`);
            }
        } else {
            this.elements.addBtn.disabled = true;
        }
    }
    
    addToCart() {
        const articleId = this.elements.articleSelect.value;
        const quantity = parseInt(this.elements.quantityInput.value) || 0;
        
        if (!articleId || quantity <= 0) {
            this.showError('يرجى اختيار مادة وكمية صحيحة');
            return;
        }
        
        const article = this.articles.find(a => a.id_article == articleId);
        if (!article) {
            this.showError('المادة غير موجودة');
            return;
        }
        
        // التحقق من وجود المادة في السلة
        const existingItemIndex = this.cartItems.findIndex(item => item.id_article == articleId);
        
        if (existingItemIndex >= 0) {
            // تحديث الكمية
            this.cartItems[existingItemIndex].quantity += quantity;
            
            // التحقق من عدم تجاوز المخزون
            if (this.cartItems[existingItemIndex].quantity > article.qte_stock) {
                this.showError(`الكمية الإجمالية تتجاوز المخزون المتاح (${article.qte_stock})`);
                this.cartItems[existingItemIndex].quantity -= quantity;
                return;
            }
        } else {
            // إضافة عنصر جديد
            this.cartItems.push({
                id_article: articleId,
                name: article.design_art,
                quantity: quantity,
                stock: article.qte_stock
            });
        }
        
        // تحديث عرض السلة
        this.updateCartDisplay();
        
        // إعادة تعيين الحقول
        this.elements.articleSelect.value = '';
        this.elements.quantityInput.value = '1';
        this.elements.addBtn.disabled = true;
        
        // تمكين زر التحقق إذا كانت السلة غير فارغة
        this.elements.validateBtn.disabled = this.cartItems.length === 0;
    }
    
    updateCartDisplay() {
        if (!this.elements.cartBody) return;
        
        this.elements.cartBody.innerHTML = '';
        
        if (this.cartItems.length === 0) {
            this.elements.cartBody.innerHTML = `
                <tr id="empty-cart">
                    <td colspan="3" class="empty-cart-message">
                        <i class="fas fa-shopping-cart"></i><br>
                        لا توجد مواد في السلة
                    </td>
                </tr>
            `;
            return;
        }
        
        this.cartItems.forEach((item, index) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${item.name}</td>
                <td>${item.quantity}</td>
                <td>
                    <button class="remove-btn" data-index="${index}">
                        <i class="fas fa-trash"></i> حذف
                    </button>
                    <button class="edit-btn" data-index="${index}">
                        <i class="fas fa-edit"></i> تعديل
                    </button>
                </td>
            `;
            
            this.elements.cartBody.appendChild(row);
        });
        
        // إضافة مستمعي الأحداث للأزرار الجديدة
        document.querySelectorAll('.remove-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const index = parseInt(e.target.closest('button').dataset.index);
                this.removeFromCart(index);
            });
        });
        
        document.querySelectorAll('.edit-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const index = parseInt(e.target.closest('button').dataset.index);
                this.editCartItem(index);
            });
        });
    }
    
    removeFromCart(index) {
        if (index >= 0 && index < this.cartItems.length) {
            this.cartItems.splice(index, 1);
            this.updateCartDisplay();
            this.elements.validateBtn.disabled = this.cartItems.length === 0;
        }
    }
    
    editCartItem(index) {
        const item = this.cartItems[index];
        if (!item) return;
        
        const newQuantity = prompt(`أدخل الكمية الجديدة لـ ${item.name} (الحد الأقصى: ${item.stock}):`, item.quantity);
        
        if (newQuantity !== null) {
            const quantity = parseInt(newQuantity);
            if (!isNaN(quantity) && quantity > 0 && quantity <= item.stock) {
                item.quantity = quantity;
                this.updateCartDisplay();
            } else {
                this.showError('الكمية غير صالحة');
            }
        }
    }
    
    async validateOrder() {
        const serviceId = this.elements.serviceSelect.value;
        
        if (!serviceId) {
            this.showError('يرجى اختيار الخدمة');
            return;
        }
        
        if (this.cartItems.length === 0) {
            this.showError('السلة فارغة. أضف مواد قبل التحقق');
            return;
        }
        
        // تأكيد من المستخدم
        if (!confirm('هل تريد تأكيد الطلب؟')) {
            return;
        }
        
        try {
            const response = await fetch('php/order.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    action: 'create',
                    serviceId: serviceId,
                    items: this.cartItems.map(item => ({
                        articleId: item.id_article,
                        quantity: item.quantity
                    })),
                    csrf_token: this.csrfToken
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                alert('تم إنشاء الطلب بنجاح!');
                
                // إعادة تعيين النموذج
                this.cartItems = [];
                this.elements.serviceSelect.value = '';
                this.updateCartDisplay();
                this.elements.validateBtn.disabled = true;
                
                // تحديث قائمة الطلبات
                await this.loadOrders();
            } else {
                this.showError(data.message || 'فشل في إنشاء الطلب');
            }
            
        } catch (error) {
            console.error('خطأ في إنشاء الطلب:', error);
            this.showError('فشل في الاتصال بالخادم');
        }
    }
    
    async loadOrders() {
        try {
            const response = await fetch('php/api.php?action=getCommandes');
            const data = await response.json();
            
            if (data.success) {
                this.allOrders = data.data;
                this.displayOrders();
            }
        } catch (error) {
            console.error('خطأ في تحميل الطلبات:', error);
        }
    }
    
    displayOrders() {
        if (!this.elements.commandsBody) return;
        
        // حساب الصفحات
        const totalPages = Math.ceil(this.allOrders.length / this.ordersPerPage);
        const startIndex = (this.currentPage - 1) * this.ordersPerPage;
        const endIndex = Math.min(startIndex + this.ordersPerPage, this.allOrders.length);
        const pageOrders = this.allOrders.slice(startIndex, endIndex);
        
        // تحديث معلومات الصفحة
        if (this.elements.paginationInfo) {
            this.elements.paginationInfo.textContent = 
                `الصفحة ${this.currentPage} من ${totalPages} (إجمالي ${this.allOrders.length} طلب)`;
        }
        
        // تحديث أزرار الصفحات
        if (this.elements.prevBtn) {
            this.elements.prevBtn.disabled = this.currentPage <= 1;
        }
        
        if (this.elements.nextBtn) {
            this.elements.nextBtn.disabled = this.currentPage >= totalPages;
        }
        
        // عرض الطلبات
        this.elements.commandsBody.innerHTML = '';
        
        if (pageOrders.length === 0) {
            this.elements.commandsBody.innerHTML = `
                <tr id="no-orders">
                    <td colspan="5" class="empty-message">
                        <i class="fas fa-inbox"></i><br>
                        لا توجد طلبات
                    </td>
                </tr>
            `;
            return;
        }
        
        pageOrders.forEach(order => {
            const row = document.createElement('tr');
            
            // تحديد لون الحالة
            let statusClass = '';
            switch(order.statut) {
                case 'en attente':
                    statusClass = 'status-pending';
                    break;
                case 'validée':
                    statusClass = 'status-validated';
                    break;
                case 'livrée':
                    statusClass = 'status-delivered';
                    break;
                case 'annulée':
                    statusClass = 'status-cancelled';
                    break;
            }
            
            row.innerHTML = `
                <td>${order.num_commande || order.Id_commande}</td>
                <td>${order.date_com}</td>
                <td>${order.service}</td>
                <td><span class="status-badge ${statusClass}">${order.statut}</span></td>
                <td>
                    <button class="details-btn" data-id="${order.Id_commande}">
                        <i class="fas fa-eye"></i> تفاصيل
                    </button>
                </td>
            `;
            
            this.elements.commandsBody.appendChild(row);
        });
        
        // إضافة مستمعي الأحداث لأزرار التفاصيل
        document.querySelectorAll('.details-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const orderId = e.target.closest('button').dataset.id;
                await this.showOrderDetails(orderId);
            });
        });
    }
    
    async showOrderDetails(orderId) {
        try {
            const response = await fetch(`php/order.php?action=details&id=${orderId}`);
            const data = await response.json();
            
            if (data.success) {
                this.selectedOrder = data.data;
                this.openOrderModal();
            } else {
                this.showError(data.message || 'فشل في تحميل التفاصيل');
            }
        } catch (error) {
            console.error('خطأ في تحميل تفاصيل الطلب:', error);
            this.showError('فشل في تحميل التفاصيل');
        }
    }
    
    openOrderModal() {
        if (!this.selectedOrder || !this.elements.modalBody) return;
        
        const order = this.selectedOrder;
        
        let itemsHtml = '';
        if (order.items && order.items.length > 0) {
            itemsHtml = `
                <h4>المواد المطلوبة:</h4>
                <table class="order-items-table">
                    <thead>
                        <tr>
                            <th>المادة</th>
                            <th>الكمية</th>
                            <th>المخزون</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${order.items.map(item => `
                            <tr>
                                <td>${item.design_art}</td>
                                <td>${item.Qte_dem}</td>
                                <td>${item.qte_stock}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
        }
        
        this.elements.modalBody.innerHTML = `
            <div class="order-details">
                <h3>الطلب رقم: ${order.Id_commande}</h3>
                <div class="order-info">
                    <p><strong>التاريخ:</strong> ${order.date_com}</p>
                    <p><strong>الخدمة:</strong> ${order.service}</p>
                    <p><strong>الحالة:</strong> ${order.statut}</p>
                    <p><strong>الموظف:</strong> ${order.Nom} ${order.Prenom}</p>
                    <p><strong>رقم التسجيل:</strong> ${order.Matricule}</p>
                    ${itemsHtml}
                    <p><strong>إجمالي المواد:</strong> ${order.total_items || 0}</p>
                    <p><strong>إجمالي الكمية:</strong> ${order.total_quantity || 0}</p>
                </div>
            </div>
        `;
        
        this.elements.orderModal.style.display = 'flex';
    }
    
    closeModal() {
        this.elements.orderModal.style.display = 'none';
        this.selectedOrder = null;
    }
    
    showError(message) {
        // يمكنك إضافة تنبيه أو عرض الرسالة في مكان مخصص
        console.error('خطأ:', message);
        alert(message);
    }
    
    showSuccess(message) {
        console.log('نجاح:', message);
        alert(message);
    }
}

// تهيئة التطبيق عند تحميل الصفحة
document.addEventListener('DOMContentLoaded', () => {
    window.app = new StockManagementApp();
});