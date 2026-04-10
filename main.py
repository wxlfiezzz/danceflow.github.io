import requests
import time
import os
import re
from datetime import datetime, timedelta
from dotenv import load_dotenv
from collections import defaultdict
import requests

load_dotenv()

# ========== КОНФИГУРАЦИЯ ==========
SUPABASE_URL = 'https://adkdzogbtsgtsvdawbit.supabase.co'
SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFka2R6b2didHNndHN2ZGF3Yml0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzU3MjQ4MDIsImV4cCI6MjA5MTMwMDgwMn0.q-FmLi_xIRvQanyJn5PGGu4xe-_gkxOWDSqIgSkPrWE'

VK_TOKEN = os.getenv('VK_GROUP_TOKEN', '')
ADMIN_ID = os.getenv('ADMIN_VK_ID', '')

# Mailo Post настройки
MAILOPOST_API_KEY = '99cc33b1d11d7aa49abc2b51a0786b22'
FROM_EMAIL = 'mihailvil15@gmail.com'
FROM_NAME = 'DanceFlow School'

last_processed_id = None

# ========== ЗАЩИТА ОТ СПАМА ==========
# Словарь для отслеживания частоты отправок на email
email_rate_limit = defaultdict(list)
# Словарь для отслеживания частоты отправок с IP (через данные записи)
ip_rate_limit = defaultdict(list)
# Блок-лист временных доменов
DISPOSABLE_DOMAINS = {
    'tempmail', '10minutemail', 'guerrillamail', 'mailinator', 'yopmail',
    'throwaway', 'sharklasers', 'temp-mail', 'spamgourmet', 'trashmail',
    'getairmail', 'mailcatch', 'guerrillamail', 'grr.la', 'mailnator',
    'tempemail', 'tempmailaddress', 'fakeinbox', 'emailfake', 'dispostable'
}

# Временные окна для rate limiting (в секундах)
EMAIL_LIMIT_WINDOW = 3600  # 1 час
EMAIL_MAX_COUNT = 1        # максимум 1 письмо на email в час

IP_LIMIT_WINDOW = 3600     # 1 час  
IP_MAX_COUNT = 3           # максимум 3 записи с одного IP в час

# ВАШ СЕКРЕТНЫЙ КЛЮЧ reCAPTCHA
RECAPTCHA_SECRET_KEY = "6LdXGrAsAAAAAOUHQTzsf4bXgVhO2DY7KPiqoIAp"

def verify_recaptcha_v3(token, action='submit'):
    """Проверка reCAPTCHA v3 токена"""
    if not token:
        return False
    
    try:
        response = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={
                'secret': RECAPTCHA_SECRET_KEY,
                'response': token
            },
            timeout=10
        )
        result = response.json()
        
        if result.get('success'):
            # reCAPTCHA v3 возвращает score от 0 до 1
            score = result.get('score', 0)
            # Если score > 0.5 - скорее всего человек
            return score > 0.5
        return False
    except Exception as e:
        print(f"Ошибка проверки reCAPTCHA: {e}")
        return False

def is_disposable_email(email):
    """Проверка на временный/одноразовый email"""
    domain = email.split('@')[-1].lower()
    # Убираем поддомены
    domain_parts = domain.split('.')
    main_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
    
    for bad in DISPOSABLE_DOMAINS:
        if bad in domain or bad in main_domain:
            return True
    return False

def is_fake_email(email):
    """Проверка на явно фейковые email"""
    fake_patterns = [
        r'^test\d*@',
        r'^fake\d*@',
        r'^example@',
        r'^user\d*@',
        r'^mail\d*@',
        r'^spam\d*@',
        r'^bot\d*@'
    ]
    for pattern in fake_patterns:
        if re.match(pattern, email, re.IGNORECASE):
            return True
    return False

def validate_email_format(email):
    """Базовая проверка формата email"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def check_email_rate_limit(email):
    """Проверка частоты отправок на один email"""
    now = time.time()
    # Очищаем старые записи
    email_rate_limit[email] = [t for t in email_rate_limit[email] if now - t < EMAIL_LIMIT_WINDOW]
    
    if len(email_rate_limit[email]) >= EMAIL_MAX_COUNT:
        return False
    email_rate_limit[email].append(now)
    return True

def validate_phone(phone):
    """Проверка формата телефона"""
    cleaned = re.sub(r'[\s\-\(\)]', '', phone)
    digits = re.sub(r'\D', '', cleaned)
    # Российские номера: 10 или 11 цифр (с 7 или 8)
    if len(digits) == 11 and (digits.startswith('7') or digits.startswith('8')):
        return True
    if len(digits) == 10:
        return True
    return False

def is_suspicious_name(name):
    """Проверка на подозрительные имена (возможные боты)"""
    suspicious = ['test', 'spam', 'bot', 'robot', 'admin', 'user', 'qwerty', 'asdf']
    name_lower = name.lower()
    for sus in suspicious:
        if sus in name_lower or name_lower == sus:
            return True
    # Слишком короткие имена
    if len(name) < 2:
        return True
    # Слишком много повторяющихся символов
    if len(set(name)) < 2 and len(name) > 3:
        return True
    return False

# ========== ФУНКЦИИ ==========
def get_records():
    """Получение записей из Supabase"""
    headers = {
        'apikey': SUPABASE_ANON_KEY,
        'Authorization': f'Bearer {SUPABASE_ANON_KEY}'
    }
    try:
        response = requests.get(
            f"{SUPABASE_URL}/rest/v1/course_enrollments",
            headers=headers,
            params={'select': '*', 'order': 'id.desc', 'limit': 20},
            timeout=30
        )
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Ошибка Supabase: {response.status_code}")
            return []
    except Exception as e:
        print(f"Ошибка: {e}")
        return []

def send_confirmation_email(to_email, first_name, last_name, phone, direction):
    """Отправляет письмо-подтверждение клиенту с защитой от спама"""
    
    # ========== ПРОВЕРКИ НА СПАМ ==========
    if not validate_email_format(to_email):
        print(f"❌ Неверный формат email: {to_email}")
        return False
    
    if is_disposable_email(to_email):
        print(f"❌ Отклонена временная почта: {to_email}")
        return False
    
    if is_fake_email(to_email):
        print(f"❌ Отклонена фейковая почта: {to_email}")
        return False
    
    if not check_email_rate_limit(to_email):
        print(f"❌ Слишком частые отправки на {to_email} (лимит {EMAIL_MAX_COUNT} в {EMAIL_LIMIT_WINDOW//3600}ч)")
        return False
    
    if is_suspicious_name(first_name) or is_suspicious_name(last_name):
        print(f"❌ Отклонено подозрительное имя: {first_name} {last_name}")
        return False
    
    if not validate_phone(phone):
        print(f"❌ Неверный формат телефона: {phone}")
        return False
    
    # Эмодзи для направления
    direction_emoji = {
        "Хастл": "💃", "Кизомба": "🕺", "Бачата": "💃", "Танго": "🕺",
        "Контемп": "💃", "Сальса": "🕺", "Реггетон": "💃", "Hip-Hop": "🕺",
        "Танцы для начинающих": "🌟", "Не знаю, нужна консультация": "❓"
    }
    emoji = direction_emoji.get(direction, "💃")
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"></head>
    <body style="font-family: Arial, sans-serif;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: linear-gradient(135deg, #ec4899, #be185d); padding: 30px; text-align: center; border-radius: 16px 16px 0 0;">
                <h1 style="color: white; margin: 0;">💃 DanceFlow</h1>
                <p style="color: #fce7f3;">Школа танцев</p>
            </div>
            <div style="background: white; padding: 30px; border-radius: 0 0 16px 16px;">
                <h2 style="color: #ec4899;">Здравствуйте, {first_name} {last_name}! 👋</h2>
                <p>Спасибо за запись на курс танцев в нашей школе!</p>
                <div style="background: #f9fafb; padding: 20px; border-radius: 12px; margin: 20px 0;">
                    <p><strong>📋 Ваши данные:</strong></p>
                    <p>📧 {to_email}</p>
                    <p>📞 {phone}</p>
                    <p>{emoji} <strong>Желаемое направление:</strong> {direction}</p>
                </div>
                <p>Наш менеджер свяжется с вами в ближайшее время.</p>
                <p>Ждём вас на танцполе! 🎉</p>
                <hr style="margin: 20px 0;">
                <p style="font-size: 12px; color: #6b7280;">© 2025 DanceFlow — Школа танцев</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    url = "https://api.mailopost.ru/v1/email/messages"
    headers = {
        'Authorization': f'Bearer {MAILOPOST_API_KEY}',
        'Content-Type': 'application/json'
    }
    
    data = {
        'from_email': FROM_EMAIL,
        'from_name': FROM_NAME,
        'to': to_email,
        'subject': f'{emoji} {first_name}, вы записаны на {direction} в DanceFlow!',
        'html': html_content,
        'text': f'Здравствуйте, {first_name}! Спасибо за запись на курс {direction}.'
    }
    
    try:
        response = requests.post(url, json=data, headers=headers, timeout=30)
        if response.status_code == 200:
            print(f"✅ Email отправлен на {to_email}")
            return True
        else:
            print(f"❌ Ошибка: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"❌ Ошибка отправки: {e}")
        return False

def send_vk_message(text):
    """Отправка сообщения администратору в VK"""
    url = "https://api.vk.com/method/messages.send"
    params = {
        'access_token': VK_TOKEN,
        'user_id': ADMIN_ID,
        'message': text,
        'random_id': int(time.time() * 1000),
        'v': '5.199'
    }
    try:
        response = requests.get(url, params=params, timeout=10)
        data = response.json()
        if 'response' in data:
            print(f"✅ VK сообщение отправлено")
            return True
        else:
            print(f"❌ Ошибка VK: {data}")
            return False
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        return False

def send_admin_notification(record):
    """Отправка уведомления администратору о новой записи"""
    direction = record.get('direction', 'Не указано')
    
    direction_emoji = {
        "Хастл": "💃", "Кизомба": "🕺", "Бачата": "💃", "Танго": "🕺",
        "Контемп": "💃", "Сальса": "🕺", "Реггетон": "💃", "Hip-Hop": "🕺",
        "Танцы для начинающих": "🌟", "Не знаю, нужна консультация": "❓"
    }
    emoji = direction_emoji.get(direction, "💃")
    
    message = f"""💃 НОВАЯ ЗАПИСЬ НА ТАНЦЫ!

📋 Клиент: {record.get('last_name', '')} {record.get('first_name', '')}
📧 Email: {record.get('email', '-')}
📞 Телефон: {record.get('phone', '-')}
{emoji} Направление: {direction}
🆔 ID записи: #{record.get('id', '-')}

✅ Свяжитесь с клиентом!"""
    
    return send_vk_message(message)

def check_new_records():
    """Проверка новых записей в Supabase"""
    global last_processed_id
    
    try:
        records = get_records()
        if not records:
            return
        
        if last_processed_id is None:
            last_processed_id = records[0]['id']
            print(f"✅ Инициализация. Последний ID: {last_processed_id}")
            send_vk_message("🤖 Бот DanceFlow запущен и защита от спама активирована!")
            return
        
        new_records = [r for r in records if r['id'] > last_processed_id]
        new_records.sort(key=lambda x: x['id'])
        
        for record in new_records:
            email = record.get('email', '')
            
            # Дополнительная проверка на спам перед отправкой
            if is_disposable_email(email):
                print(f"⚠️ Пропущена отправка для спам-почты: {email}")
                last_processed_id = record['id']
                continue
            
            print(f"\n📝 Новая запись #{record['id']}")
            print(f"   Клиент: {record.get('last_name', '')} {record.get('first_name', '')}")
            print(f"   Email: {email}")
            print(f"   Направление: {record.get('direction', 'Не указано')}")
            
            # Отправляем уведомление админу (всегда)
            send_admin_notification(record)
            
            # Отправляем email клиенту (только если прошёл проверки)
            send_confirmation_email(
                to_email=email,
                first_name=record.get('first_name'),
                last_name=record.get('last_name'),
                phone=record.get('phone'),
                direction=record.get('direction', 'не выбрано')
            )
            
            last_processed_id = record['id']
            print(f"✅ Запись #{record['id']} обработана")
            time.sleep(2)
            
    except Exception as e:
        print(f"❌ Ошибка: {e}")

def main():
    print("=" * 60)
    print("🤖 VK БОТ DANCEFLOW + MAILO POST (С ЗАЩИТОЙ ОТ СПАМА)")
    print("=" * 60)
    print("\n🛡️ Активирована защита от спама:")
    print(f"   - Блокировка временных почт (mailinator, tempmail и др.)")
    print(f"   - Rate limit: {EMAIL_MAX_COUNT} письмо/час на email")
    print(f"   - Проверка формата телефона и email")
    print(f"   - Блокировка подозрительных имен")
    print("=" * 60)
    
    if not VK_TOKEN:
        print("❌ VK_GROUP_TOKEN не указан в .env")
        return
    
    records = get_records()
    global last_processed_id
    if records:
        last_processed_id = records[0]['id']
        print(f"✅ Последний ID записи: {last_processed_id}")
    
    print("✅ Бот запущен! Проверка каждые 10 секунд...")
    print("=" * 60)
    
    while True:
        try:
            check_new_records()
            time.sleep(10)
        except KeyboardInterrupt:
            print("\n👋 Бот остановлен")
            break
        except Exception as e:
            print(f"❌ Ошибка: {e}")
            time.sleep(15)

if __name__ == "__main__":
    main()