# Postfix TLS Policy Maps - SQL Proxy

If you don't want to use a plain file Postfix lookup table to manage TLS policy maps, but a SQL backend, you'll very likely find the files in this directory helpful. You can use them as follows:

1. Create a `tls_policy` table in the SQL database you want to use with Postfix. You can use the provided [`scheme.sql`](scheme.sql) if you want to.

2. Create a proxy configuration file (e.g. `/etc/postfix/tls_policy.cf`) to tell Postfix the SQL query to use. You can again use the provided [`postfix_proxy.cf`](postfix_proxy.cf) as a blueprint, but don't forget to change username and password.

3. Configure Postfix to actually use the proxy configuration file by setting the `smtp_tls_policy_maps` parameter in Postfix's `main.cf` accordingly. Don't forget to reload/restart Postfix afterwards.
   ```
   smtp_tls_policy_maps = mysql:/etc/postfix/tls_policy.cf
   ```

4. Use the provided [`update_database.sh`](update_database.sh) to convert the plain file Postfix lookup table to SQL queries and execute them. You can e.g. simply pipe stdout of the script to the `mysql` command.
   ```
   $ ./update_database.sh ../tls_policy | mysql --user=db_user --password "db_name"
   ```
   You can change the built-in SQL query template by setting the environment variable `TEMPLATE`. You can use the placeholders `{domain}`, `{policy}` and `{params}` in the template. As a reference, this is the script's default template:
   ```
   DELETE FROM tls_policy WHERE domain = '{domain}'; INSERT INTO tls_policy (domain, policy, params) VALUES ('{domain}', '{policy}', '{params}');
   ```

5. You may want to repeat Step 4 on a regular basis (e.g. weekly) to always use the newest upstream TLS policy maps on your server. The provided `update_database.sh` always validates the policy file before converting it into SQL queries, so you can safely automatize this task with a cronjob. The following crontab line is intended to provide inspiration for you to create your own cronjob (it will work with Debian only). Most importantly, you'll have to find a way to safely pass the password of the SQL user to the cronjob.
   ```
   0 4	* * 7	root	curl -sS "https://raw.githubusercontent.com/csware/postfix-tls-policy/master/tls_policy" | /path/to/update_database.sh - | mysql --defaults-file="/etc/mysql/debian.cnf" --silent "db_name"
   ```

