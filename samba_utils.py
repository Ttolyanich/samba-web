import os
import re
import subprocess

def parse_smb_conf(conf_path):
    """
    Парсит smb.conf, находит секции (шары) и вытаскивает ассоциированные
    группы доступа (RW и RO) из параметров valid users, write list, read list.
    """
    shares = []
    current_share = None
    
    if not os.path.exists(conf_path):
        return shares
        
    try:
        with open(conf_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading smb.conf: {e}")
        return shares

    for line in lines:
        line = line.strip()
        # Игнорируем комментарии и пустые строки
        if not line or line.startswith('#') or line.startswith(';'):
            continue
            
        # Начало новой секции
        if line.startswith('[') and line.endswith(']'):
            section_name = line[1:-1].strip()
            # Пропускаем глобальные секции и принтеры
            if section_name.lower() in ['global', 'homes', 'printers', 'print$']:
                current_share = None
            else:
                current_share = {
                    "name": section_name,
                    "path": "",
                    "valid_users": [],
                    "write_list": [],
                    "read_list": [],
                    "rw_group": "",
                    "ro_group": ""
                }
                shares.append(current_share)
        # Параметры секции
        elif current_share is not None and '=' in line:
            key, val = line.split('=', 1)
            key = key.strip().lower()
            val = val.strip()
            
            if key == 'path':
                current_share['path'] = val
            elif key == 'valid users':
                current_share['valid_users'] = [u.strip() for u in val.split(',') if u.strip()]
            elif key == 'write list':
                current_share['write_list'] = [u.strip() for u in val.split(',') if u.strip()]
            elif key == 'read list':
                current_share['read_list'] = [u.strip() for u in val.split(',') if u.strip()]

    # Вытаскиваем RW и RO группы для каждой шары
    for share in shares:
        groups = []
        # Собираем все упоминания групп (начинаются с @ или +)
        for item in share['valid_users'] + share['write_list'] + share['read_list']:
            if item.startswith('@') or item.startswith('+'):
                grp = item[1:]
                if grp not in groups:
                    groups.append(grp)
        
        # Определяем RW группу (обычно указана в write list)
        rw_candidates = [u[1:] for u in share['write_list'] if u.startswith('@') or u.startswith('+')]
        ro_candidates = [u[1:] for u in share['read_list'] if u.startswith('@') or u.startswith('+')]
        
        if rw_candidates:
            share['rw_group'] = rw_candidates[0]
        elif groups:
            # Если нет явного write list, но есть группы, RW - та, что без суффикса "-r"
            non_r = [g for g in groups if not g.endswith('-r')]
            share['rw_group'] = non_r[0] if non_r else groups[0]
            
        if ro_candidates:
            # RO - это группа из read list, которая не является RW группой
            ro_grps = [g for g in ro_candidates if g != share['rw_group']]
            if ro_grps:
                share['ro_group'] = ro_grps[0]
            else:
                # Если в read list нет отличий, ищем группу с суффиксом "-r"
                r_grps = [g for g in groups if g.endswith('-r')]
                if r_grps:
                    share['ro_group'] = r_grps[0]
        elif groups and not share['ro_group']:
            # В крайнем случае, если есть группа с суффиксом "-r"
            r_grps = [g for g in groups if g.endswith('-r')]
            if r_grps:
                share['ro_group'] = r_grps[0]
                
    return shares

def get_samba_users():
    """
    Получает список пользователей Samba с помощью `pdbedit -L -v`
    и определяет их статус блокировки и полное имя.
    """
    try:
        res = subprocess.run(["sudo", "pdbedit", "-L", "-v"], capture_output=True, text=True, check=True)
        output = res.stdout
    except Exception as e:
        print(f"Error running pdbedit: {e}")
        return []
        
    users = []
    current_user = None
    
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Unix username:"):
            username = line.split(":", 1)[1].strip()
            current_user = {"username": username, "disabled": False, "full_name": ""}
            users.append(current_user)
        elif line.startswith("Full Name:") and current_user is not None:
            current_user["full_name"] = line.split(":", 1)[1].strip()
        elif line.startswith("Account Flags:") and current_user is not None:
            flags_part = line.split(":", 1)[1].strip()
            # Например: [DU         ] или [U          ]
            m = re.search(r"\[(.*?)\]", flags_part)
            if m:
                flags = m.group(1)
                if 'D' in flags:
                    current_user["disabled"] = True
                    
    return users

def get_user_groups(username):
    """
    Получает все группы, в которых состоит пользователь (через id -Gn)
    """
    try:
        res = subprocess.run(["id", "-Gn", username], capture_output=True, text=True, check=True)
        return [g.strip() for g in res.stdout.split()]
    except Exception:
        return []

def ensure_group_exists(groupname):
    """
    Создает группу ОС, если она не существует
    """
    try:
        subprocess.run(["sudo", "groupadd", "-f", groupname], check=True)
        return True
    except Exception as e:
        print(f"Error creating group {groupname}: {e}")
        return False

def add_user_to_group(username, groupname):
    """
    Добавляет пользователя в группу ОС
    """
    ensure_group_exists(groupname)
    try:
        subprocess.run(["sudo", "gpasswd", "-a", username, groupname], check=True, capture_output=True)
        return True
    except Exception as e:
        print(f"Error adding {username} to {groupname}: {e}")
        return False

def remove_user_from_group(username, groupname):
    """
    Удаляет пользователя из группы ОС
    """
    try:
        subprocess.run(["sudo", "gpasswd", "-d", username, groupname], check=True, capture_output=True)
        return True
    except Exception as e:
        print(f"Error removing {username} from {groupname}: {e}")
        return False

def system_user_exists(username):
    """
    Проверяет существование пользователя в ОС
    """
    try:
        subprocess.run(["id", username], check=True, capture_output=True)
        return True
    except Exception:
        return False

def create_samba_user(username, password, full_name=""):
    """
    Создает системного пользователя с полным именем и пользователя Samba
    """
    if not system_user_exists(username):
        try:
            # Создаем системного пользователя без домашней директории для входа (nologin)
            cmd = ["sudo", "useradd", "-m", "-s", "/usr/sbin/nologin", username]
            if full_name:
                cmd += ["-c", full_name]
            subprocess.run(cmd, check=True, capture_output=True)
        except Exception as e:
            print(f"Error creating OS user: {e}")
            return False, "Ошибка создания пользователя в ОС"
            
    try:
        # Устанавливаем пароль в Samba через smbpasswd
        proc = subprocess.Popen(["sudo", "smbpasswd", "-a", "-s", username], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.communicate(input=f"{password}\n{password}\n")
        if proc.returncode != 0:
            return False, f"Ошибка smbpasswd: {stderr.strip()}"
            
        # Устанавливаем Full Name в Samba
        if full_name:
            subprocess.run(["sudo", "pdbedit", "-r", "-u", username, "-f", full_name], check=True, capture_output=True)
            
        return True, "Пользователь успешно создан в Samba"
    except Exception as e:
        print(f"Error in smbpasswd/pdbedit: {e}")
        return False, str(e)

def block_samba_user(username):
    """
    Блокирует доступ пользователя в Samba (-d)
    """
    try:
        subprocess.run(["sudo", "smbpasswd", "-d", username], check=True, capture_output=True)
        return True
    except Exception as e:
        print(f"Error blocking user {username}: {e}")
        return False

def unblock_samba_user(username):
    """
    Разблокирует доступ пользователя в Samba (-e)
    """
    try:
        subprocess.run(["sudo", "smbpasswd", "-e", username], check=True, capture_output=True)
        return True
    except Exception as e:
        print(f"Error unblocking user {username}: {e}")
        return False

def reset_samba_password(username, password):
    """
    Сбрасывает пароль пользователя в Samba
    """
    try:
        proc = subprocess.Popen(["sudo", "smbpasswd", "-a", "-s", username], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.communicate(input=f"{password}\n{password}\n")
        if proc.returncode != 0:
            return False, f"Ошибка smbpasswd: {stderr.strip()}"
        return True, "Пароль успешно сброшен"
    except Exception as e:
        print(f"Error resetting password for {username}: {e}")
        return False, str(e)

def rename_samba_user(old_username, new_username, new_fullname):
    """
    Переименовывает пользователя в Linux ОС и Samba passdb с сохранением хэша пароля,
    либо просто изменяет ФИО (если логин остался прежним).
    """
    if old_username == new_username:
        try:
            # Обновляем ФИО в ОС
            subprocess.run(["sudo", "usermod", "-c", new_fullname, old_username], check=True, capture_output=True)
            # Обновляем ФИО в Samba
            subprocess.run(["sudo", "pdbedit", "-r", "-u", old_username, "-f", new_fullname], check=True, capture_output=True)
            return True, "ФИО сотрудника успешно изменено"
        except Exception as e:
            print(f"Error updating fullname for {old_username}: {e}")
            return False, f"Ошибка обновления ФИО: {e}"

    # Если логин изменился, переносим аккаунт с сохранением хэша пароля
    nt_hash = ""
    try:
        res = subprocess.run(["sudo", "pdbedit", "-w", "-u", old_username], capture_output=True, text=True, check=True)
        parts = res.stdout.strip().split(":")
        if len(parts) >= 4:
            nt_hash = parts[3]
    except Exception as e:
        print(f"Error getting old NT hash for {old_username}: {e}")

    try:
        # 1. Переименовываем системного пользователя в Linux и обновляем комментарий (ФИО)
        subprocess.run(["sudo", "usermod", "-l", new_username, "-c", new_fullname, old_username], check=True, capture_output=True)
    except Exception as e:
        print(f"Error renaming Linux user from {old_username} to {new_username}: {e}")
        return False, f"Ошибка переименования в ОС: {e}"

    try:
        # 2. Создаем нового пользователя в Samba
        proc = subprocess.Popen(["sudo", "smbpasswd", "-a", "-s", new_username], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.communicate(input="dummypassword\ndummypassword\n")
        if proc.returncode != 0:
            return False, f"Ошибка smbpasswd: {stderr.strip()}"

        # 3. Восстанавливаем старый хэш пароля
        if nt_hash and nt_hash != "X" * 32:
            subprocess.run(["sudo", "pdbedit", "-r", "-u", new_username, f"--set-nt-hash={nt_hash}"], check=True, capture_output=True)

        # 4. Устанавливаем ФИО в Samba для новой учетной записи
        if new_fullname:
            subprocess.run(["sudo", "pdbedit", "-r", "-u", new_username, "-f", new_fullname], check=True, capture_output=True)

        # 5. Удаляем старый Samba-аккаунт
        subprocess.run(["sudo", "pdbedit", "-x", "-u", old_username], check=True, capture_output=True)

        return True, "Пользователь успешно переименован"
    except Exception as e:
        print(f"Error migrating Samba settings for {new_username}: {e}")
        return False, f"Ошибка миграции Samba-аккаунта: {e}"
