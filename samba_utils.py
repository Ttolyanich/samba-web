import os
import re
import subprocess

USE_NSENTER = os.environ.get("USE_NSENTER", "false").lower() == "true"

def run_system_command(cmd, **kwargs):
    """
    Выполняет системную команду. Если включен режим USE_NSENTER,
    выполняет её на хост-системе через nsenter.
    """
    if USE_NSENTER:
        nsenter_prefix = ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--"]
        if cmd[0] == "sudo":
            cmd = cmd[1:]
        full_cmd = nsenter_prefix + cmd
    else:
        full_cmd = cmd
        
    return subprocess.run(full_cmd, **kwargs)

def system_popen(cmd, **kwargs):
    """
    Создает процесс Popen. Если включен USE_NSENTER,
    запускает команду на хосте через nsenter.
    """
    if USE_NSENTER:
        nsenter_prefix = ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--"]
        if cmd[0] == "sudo":
            cmd = cmd[1:]
        full_cmd = nsenter_prefix + cmd
    else:
        full_cmd = cmd
        
    return subprocess.Popen(full_cmd, **kwargs)

def system_path_exists(path):
    """
    Проверяет существование пути. Если включен USE_NSENTER, проверяет на хосте через test -e.
    """
    if USE_NSENTER:
        cmd = ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--", "test", "-e", path]
        res = subprocess.run(cmd)
        return res.returncode == 0
    else:
        return os.path.exists(path)

def parse_smb_conf(conf_path):
    """
    Парсит smb.conf, находит секции (шары) и вытаскивает ассоциированные
    группы доступа (RW и RO) из параметров valid users, write list, read list.
    """
    shares = []
    current_share = None
    
    if not system_path_exists(conf_path):
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
                    "vfs_objects": "",
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
            elif key == 'vfs objects':
                current_share['vfs_objects'] = val

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
        res = run_system_command(["sudo", "pdbedit", "-L", "-v"], capture_output=True, text=True, check=True)
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
        res = run_system_command(["id", "-Gn", username], capture_output=True, text=True, check=True)
        return [g.strip() for g in res.stdout.split()]
    except Exception:
        return []

def ensure_group_exists(groupname):
    """
    Создает группу ОС, если она не существует
    """
    try:
        run_system_command(["sudo", "groupadd", "-f", groupname], check=True)
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
        run_system_command(["sudo", "gpasswd", "-a", username, groupname], check=True, capture_output=True)
        return True
    except Exception as e:
        print(f"Error adding {username} to {groupname}: {e}")
        return False

def remove_user_from_group(username, groupname):
    """
    Удаляет пользователя из группы ОС
    """
    try:
        run_system_command(["sudo", "gpasswd", "-d", username, groupname], check=True, capture_output=True)
        return True
    except Exception as e:
        print(f"Error removing {username} from {groupname}: {e}")
        return False

def system_user_exists(username):
    """
    Проверяет существование пользователя в ОС
    """
    try:
        run_system_command(["id", username], check=True, capture_output=True)
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
            run_system_command(cmd, check=True, capture_output=True)
        except Exception as e:
            print(f"Error creating OS user: {e}")
            return False, "Ошибка создания пользователя в ОС"
            
    try:
        # Устанавливаем пароль в Samba через smbpasswd
        proc = system_popen(["sudo", "smbpasswd", "-a", "-s", username], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.communicate(input=f"{password}\n{password}\n")
        if proc.returncode != 0:
            return False, f"Ошибка smbpasswd: {stderr.strip()}"
            
        # Устанавливаем Full Name в Samba
        if full_name:
            run_system_command(["sudo", "pdbedit", "-r", "-u", username, "-f", full_name], check=True, capture_output=True)
            
        return True, "Пользователь успешно создан в Samba"
    except Exception as e:
        print(f"Error in smbpasswd/pdbedit: {e}")
        return False, str(e)

def block_samba_user(username):
    """
    Блокирует доступ пользователя в Samba (-d)
    """
    try:
        run_system_command(["sudo", "smbpasswd", "-d", username], check=True, capture_output=True)
        return True
    except Exception as e:
        print(f"Error blocking user {username}: {e}")
        return False

def unblock_samba_user(username):
    """
    Разблокирует доступ пользователя в Samba (-e)
    """
    try:
        run_system_command(["sudo", "smbpasswd", "-e", username], check=True, capture_output=True)
        return True
    except Exception as e:
        print(f"Error unblocking user {username}: {e}")
        return False

def reset_samba_password(username, password):
    """
    Сбрасывает пароль пользователя в Samba
    """
    try:
        proc = system_popen(["sudo", "smbpasswd", "-a", "-s", username], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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
            run_system_command(["sudo", "usermod", "-c", new_fullname, old_username], check=True, capture_output=True)
            # Обновляем ФИО в Samba
            run_system_command(["sudo", "pdbedit", "-r", "-u", old_username, "-f", new_fullname], check=True, capture_output=True)
            return True, "ФИО сотрудника успешно изменено"
        except Exception as e:
            print(f"Error updating fullname for {old_username}: {e}")
            return False, f"Ошибка обновления ФИО: {e}"

    # Если логин изменился, переносим аккаунт с сохранением хэша пароля
    nt_hash = ""
    try:
        res = run_system_command(["sudo", "pdbedit", "-w", "-u", old_username], capture_output=True, text=True, check=True)
        parts = res.stdout.strip().split(":")
        if len(parts) >= 4:
            nt_hash = parts[3]
    except Exception as e:
        print(f"Error getting old NT hash for {old_username}: {e}")

    try:
        # 1. Переименовываем системного пользователя в Linux и обновляем комментарий (ФИО)
        run_system_command(["sudo", "usermod", "-l", new_username, "-c", new_fullname, old_username], check=True, capture_output=True)
    except Exception as e:
        print(f"Error renaming Linux user from {old_username} to {new_username}: {e}")
        return False, f"Ошибка переименования в ОС: {e}"

    try:
        # 2. Создаем нового пользователя в Samba
        proc = system_popen(["sudo", "smbpasswd", "-a", "-s", new_username], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.communicate(input="dummypassword\ndummypassword\n")
        if proc.returncode != 0:
            return False, f"Ошибка smbpasswd: {stderr.strip()}"

        # 3. Восстанавливаем старый хэш пароля
        if nt_hash and nt_hash != "X" * 32:
            run_system_command(["sudo", "pdbedit", "-r", "-u", new_username, f"--set-nt-hash={nt_hash}"], check=True, capture_output=True)

        # 4. Устанавливаем ФИО в Samba для новой учетной записи
        if new_fullname:
            run_system_command(["sudo", "pdbedit", "-r", "-u", new_username, "-f", new_fullname], check=True, capture_output=True)

        # 5. Удаляем старый Samba-аккаунт
        run_system_command(["sudo", "pdbedit", "-x", "-u", old_username], check=True, capture_output=True)

        return True, "Пользователь успешно переименован"
    except Exception as e:
        print(f"Error migrating Samba settings for {new_username}: {e}")
        return False, f"Ошибка миграции Samba-аккаунта: {e}"

def get_directory_acl_groups(dir_path):
    """
    Выполняет getfacl для директории и извлекает группы с правами rwx (RW) и r-x (RO).
    Если getfacl не установлен или завершился с ошибкой, берет стандартную Unix-группу владельца.
    На Windows возвращает заглушки на основе имени папки для локального тестирования.
    """
    import sys
    if sys.platform == 'win32':
        base_name = os.path.basename(dir_path)
        if not base_name or base_name == '/' or base_name == 'share':
            return "", ""
        if base_name == "Бухгалтерия":
            return "G-buh", "G-buh-r"
        elif base_name == "Общая":
            return "G-shared", "G-shared-r"
        elif base_name == "oll":
            return "G-oll", "G-oll-r"
        elif base_name == "Clients":
            return "G-oll-Clients", "G-oll-Clients-r"
        elif base_name == "2016":
            return "G-oll-Clients-2016", "G-oll-Clients-2016-r"
        else:
            clean_name = re.sub(r'[^a-zA-Z0-9_-]', '', base_name)
            return f"G-{clean_name}", f"G-{clean_name}-r"

    rw_group = ""
    ro_group = ""

    # 1. Попытка выполнить getfacl
    try:
        res = run_system_command(["sudo", "getfacl", "-p", "-E", dir_path], capture_output=True, text=True, check=True)
        output = res.stdout
        
        rw_groups = []
        ro_groups = []

        for line in output.splitlines():
            line = line.strip()
            if line.startswith("group:"):
                parts = line.split(":")
                if len(parts) >= 3:
                    group_name = parts[1]
                    perms = parts[2]
                    if not group_name:
                        continue
                    if perms == "rwx":
                        rw_groups.append(group_name)
                    elif perms == "r-x" or perms == "rx":
                        ro_groups.append(group_name)

        rw_group = rw_groups[0] if rw_groups else ""
        ro_group = ro_groups[0] if ro_groups else ""
    except Exception as e:
        print(f"getfacl failed on {dir_path}: {e}")

    # 2. Фолбек: если getfacl не дал групп, берем Unix-группу владельца
    if not rw_group:
        try:
            res_owner = run_system_command(["stat", "-c", "%G", dir_path], capture_output=True, text=True)
            owner_group = res_owner.stdout.strip()
            # Проверяем наш стандарт (начинается с G-)
            if owner_group.startswith("G-"):
                rw_group = owner_group
                # Проверяем наличие RO группы (с суффиксом -r) в ОС
                ro_candidate = f"{owner_group}-r"
                res_grp = run_system_command(["getent", "group", ro_candidate])
                if res_grp.returncode == 0:
                    ro_group = ro_candidate
                else:
                    ro_group = ""
        except Exception as e:
            print(f"Fallback to Unix group owner failed for {dir_path}: {e}")

    return rw_group, ro_group

def scan_directories_acl(share_path, max_depth=3):
    """
    Находит все подкаталоги до max_depth с помощью find, а затем запрашивает их ACL
    в ОДНОМ пакетном вызове getfacl для исключения оверхеда и рекурсивного сканирования файлов.
    """
    acl_map = {}
    
    # 1. Находим только папки до нужной глубины (файлы игнорируются, это мгновенно)
    try:
        cmd = ["sudo", "find", share_path, "-mindepth", "1", "-maxdepth", str(max_depth), "-type", "d"]
        res = run_system_command(cmd, capture_output=True, text=True, check=True)
        dir_paths = res.stdout.splitlines()
    except Exception as e:
        print(f"Error running find on {share_path}: {e}")
        dir_paths = []

    # Добавляем сам корень ресурса
    dir_paths.append(share_path)
    
    # Очищаем пути и фильтруем скрытые папки
    clean_paths = []
    for p in dir_paths:
        p = p.strip()
        if not p:
            continue
        rel_path = os.path.relpath(p, share_path)
        parts = rel_path.split(os.sep)
        if p != share_path and any(part.startswith('.') for part in parts):
            continue
        clean_paths.append(p)

    if not clean_paths:
        return acl_map

    # 2. Получаем ACL для всех отфильтрованных путей за один вызов
    try:
        cmd = ["sudo", "getfacl", "-p", "-E"] + clean_paths
        res = run_system_command(cmd, capture_output=True, text=True, check=True)
        output = res.stdout
    except Exception as e:
        print(f"Error running batch getfacl on {share_path}: {e}")
        return acl_map

    current_path = None
    rw_groups = []
    ro_groups = []
    owner_group = ""

    def save_current():
        if current_path:
            rw = rw_groups[0] if rw_groups else ""
            ro = ro_groups[0] if ro_groups else ""
            
            # Фолбек на Unix-группу владельца
            if not rw and owner_group.startswith("G-"):
                rw = owner_group
                
            acl_map[current_path] = (rw, ro, owner_group)

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
            
        if line.startswith("# file:"):
            save_current()
            
            raw_path = line.split(":", 1)[1].strip()
            # Декодируем октальные последовательности (\040 -> пробел)
            import re
            def octal_replace(match):
                return chr(int(match.group(1), 8))
            current_path = re.sub(r'\\([0-7]{3})', octal_replace, raw_path)
            
            # Убираем экранирование обратных слэшей
            current_path = current_path.replace("\\ ", " ")
            
            if not current_path.startswith("/"):
                current_path = "/" + current_path
                
            rw_groups = []
            ro_groups = []
            owner_group = ""
            
        elif line.startswith("# group:"):
            owner_group = line.split(":", 1)[1].strip()
            
        elif line.startswith("group:"):
            parts = line.split(":")
            if len(parts) >= 3:
                gname = parts[1]
                perms = parts[2]
                if gname and gname.startswith("G-"):
                    if perms == "rwx":
                        rw_groups.append(gname)
                    elif perms in ("r-x", "rx"):
                        ro_groups.append(gname)
                        
    save_current()
    return acl_map

def discover_acl_resources(smb_conf_path, max_depth=3):
    """
    Сканирует корневые директории общих ресурсов Samba и находит вложенные папки,
    которые имеют отличающиеся группы доступа (границы безопасности).
    """
    shares = parse_smb_conf(smb_conf_path)
    resources = []
    
    import sys
    if sys.platform == 'win32':
        mock_resources = [
            {
                "name": "Бухгалтерия",
                "display_name": "Бухгалтерия",
                "path": "/share/Бухгалтерия",
                "depth": 0,
                "parent": None,
                "rw_group": "G-buh",
                "ro_group": "G-buh-r"
            },
            {
                "name": "Общая",
                "display_name": "Общая",
                "path": "/share/Общая",
                "depth": 0,
                "parent": None,
                "rw_group": "G-shared",
                "ro_group": "G-shared-r"
            },
            {
                "name": "Общая / oll",
                "display_name": "oll",
                "path": "/share/Общая/oll",
                "depth": 1,
                "parent": "Общая",
                "rw_group": "G-oll",
                "ro_group": "G-oll-r"
            },
            {
                "name": "Общая / oll / Clients",
                "display_name": "Clients",
                "path": "/share/Общая/oll/Clients",
                "depth": 2,
                "parent": "Общая / oll",
                "rw_group": "G-oll-Clients",
                "ro_group": "G-oll-Clients-r"
            },
            {
                "name": "Общая / oll / Clients / 2016",
                "display_name": "2016",
                "path": "/share/Общая/oll/Clients/2016",
                "depth": 3,
                "parent": "Общая / oll / Clients",
                "rw_group": "G-oll-Clients-2016",
                "ro_group": "G-oll-Clients-2016-r"
            }
        ]
        for i, res in enumerate(mock_resources):
            has_child = any(other["parent"] == res["name"] for other in mock_resources)
            mock_resources[i]["has_children"] = has_child
        return mock_resources

    import grp
    # Кэшируем существование RO групп в ОС, чтобы не делать getent в цикле
    _group_cache = {}
    def check_ro_group_exists(ro_name):
        if ro_name in _group_cache:
            return _group_cache[ro_name]
        res_grp = run_system_command(["getent", "group", ro_name])
        exists = (res_grp.returncode == 0)
        _group_cache[ro_name] = exists
        return exists

    for share in shares:
        share_path = share["path"]
        if not share_path or not system_path_exists(share_path):
            continue
            
        # Проверяем, настроен ли ACL для ресурса в smb.conf (через группы или vfs objects)
        is_acl_share = "acl_xattr" in share.get("vfs_objects", "") or share.get("rw_group") or share.get("ro_group")
        
        # Считываем права для корня в любом случае
        root_data = get_directory_acl_groups(share_path)
        rw_grp = root_data[0]
        ro_grp = root_data[1]
        
        if not rw_grp and share.get("rw_group"):
            rw_grp = share["rw_group"]
        if not ro_grp and share.get("ro_group"):
            ro_grp = share["ro_group"]
            
        if not ro_grp and rw_grp:
            ro_grp = f"{rw_grp}-r" if check_ro_group_exists(f"{rw_grp}-r") else ""
            
        root_resource = {
            "name": share["name"],
            "display_name": share["name"],
            "path": share_path,
            "depth": 0,
            "parent": None,
            "rw_group": rw_grp,
            "ro_group": ro_grp
        }
        
        # Если это не ACL ресурс, добавляем только корень и не сканируем вложенные папки
        if not is_acl_share:
            root_resource["has_children"] = False
            resources.append(root_resource)
            continue
            
        share_resources = [root_resource]
        
        # Выполняем точечное быстрое сканирование
        acl_map = scan_directories_acl(share_path, max_depth)
        
        # Фильтруем папки
        dir_entries = []
        for path, data in acl_map.items():
            if path == share_path:
                continue
                
            rel_path = os.path.relpath(path, share_path)
            parts = rel_path.split(os.sep)
            
            # Пропускаем скрытые папки и слишком глубокие
            if any(p.startswith('.') for p in parts) or len(parts) > max_depth:
                continue
                
            dir_entries.append((path, parts, data))
                
        # Сортируем по чистому пути для depth-first обхода
        dir_entries.sort(key=lambda x: x[0])
        
        for path, parts, data in dir_entries:
            rw = data[0]
            ro = data[1]
            owner_group = data[2]
            
            # Фолбек на Unix группу владельца
            if not rw and owner_group.startswith("G-"):
                rw = owner_group
                
            # Системная проверка RO группы
            if rw and not ro:
                ro = f"{rw}-r" if check_ro_group_exists(f"{rw}-r") else ""
                
            if rw or ro:
                # Ищем ближайшего включенного предка
                parent_path = os.path.dirname(path)
                ancestor = None
                while len(parent_path) >= len(share_path):
                    match = next((r for r in share_resources if r["path"] == parent_path), None)
                    if match:
                        ancestor = match
                        break
                    parent_path = os.path.dirname(parent_path)
                    
                if not ancestor:
                    ancestor = root_resource
                    
                # Сравниваем группы с ближайшим включенным предком
                if rw == ancestor["rw_group"] and ro == ancestor["ro_group"]:
                    continue
                    
                # Добавляем как отдельный управляемый ресурс
                display_name = parts[-1]
                visual_depth = ancestor["depth"] + 1
                
                res_name = f"{ancestor['name']} / {display_name}"
                
                share_resources.append({
                    "name": res_name,
                    "display_name": display_name,
                    "path": path,
                    "depth": visual_depth,
                    "parent": ancestor["name"],
                    "rw_group": rw,
                    "ro_group": ro
                })
                
        resources.extend(share_resources)
        
    for i, res in enumerate(resources):
        has_child = any(other["parent"] == res["name"] for other in resources)
        resources[i]["has_children"] = has_child
        
    return resources

def reset_user_samba_sessions(username):
    """
    Находит все активные процессы smbd для данного пользователя через smbstatus
    и завершает их (kill), заставляя Windows-клиент пересоздать сессию с новыми правами.
    """
    pids = []
    try:
        # Запускаем smbstatus -p для получения списка процессов
        res = run_system_command(["sudo", "smbstatus", "-p"], capture_output=True, text=True, check=True)
        lines = res.stdout.splitlines()
        
        # Парсим вывод
        for line in lines:
            line = line.strip()
            if not line or line.startswith("Samba version") or line.startswith("PID") or line.startswith("---"):
                continue
            
            parts = line.split()
            if len(parts) >= 2:
                pid = parts[0]
                user = parts[1]
                if user == username:
                    pids.append(pid)
    except Exception as e:
        print(f"Error running smbstatus: {e}")
        return False, f"Ошибка получения статуса Samba: {e}"

    if not pids:
        return True, "Активных сессий пользователя не найдено (сброс не требуется)"

    # Завершаем процессы
    killed_count = 0
    errors = []
    for pid in pids:
        try:
            run_system_command(["sudo", "kill", pid], check=True)
            killed_count += 1
        except Exception as e:
            errors.append(f"PID {pid}: {e}")

    if errors:
        return False, f"Сброшено сессий: {killed_count}. Ошибки: {', '.join(errors)}"
    
    return True, f"Успешно сброшено активных сессий: {killed_count}"


