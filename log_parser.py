import re
import pandas as pd
import matplotlib.pyplot as plt

# -------------------------------
# 1️⃣ Apache log parsing
# -------------------------------
apache_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<time>.*?)\] "(?P<method>\w+) (?P<url>\S+) \S+" (?P<status>\d{3}) (?P<size>\d+)'
)

def parse_apache_log(file_path):
    logs = []
    with open(file_path, "r") as f:
        for line in f:
            match = apache_pattern.match(line)
            if match:
                logs.append(match.groupdict())
    df = pd.DataFrame(logs)
    return df

# -------------------------------
# 2️⃣ SSH auth.log parsing
# -------------------------------
auth_pattern = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

def parse_auth_log(file_path):
    logs = []
    with open(file_path, "r") as f:
        for line in f:
            match = auth_pattern.search(line)
            if match:
                logs.append(match.groupdict())
    df = pd.DataFrame(logs)
    return df

# -------------------------------
# 3️⃣ Load logs
# -------------------------------
apache_log_file = "access.log"    # your Apache log file
auth_log_file   = "auth.log"      # your SSH log file

apache_df = parse_apache_log(apache_log_file)
auth_df   = parse_auth_log(auth_log_file)

# -------------------------------
# 4️⃣ Apache log analysis
# -------------------------------
print("\n📊 Apache Log Data (first 5 rows):")
print(apache_df.head())

print("\n🔎 Status Code Counts:")
print(apache_df["status"].value_counts())

print("\n🔎 Top 5 IPs accessing Apache:")
print(apache_df["ip"].value_counts().head(5))

# Plot HTTP status codes
apache_df["status"].value_counts().plot(kind="bar", color="skyblue")
plt.title("Apache HTTP Status Code Distribution")
plt.xlabel("Status Code")
plt.ylabel("Count")
plt.show()

# -------------------------------
# 5️⃣ SSH auth.log analysis
# -------------------------------
print("\n📊 SSH Failed Login Attempts (first 5 rows):")
print(auth_df.head())

print("\n🚨 Failed SSH attempts by IP:")
print(auth_df["ip"].value_counts())

# Plot failed SSH attempts by IP
auth_df["ip"].value_counts().plot(kind="bar", color="salmon")
plt.title("Failed SSH Login Attempts by IP")
plt.xlabel("IP Address")
plt.ylabel("Count")
plt.show()


