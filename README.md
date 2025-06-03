Let’s dive into a detailed line-by-line explanation of the `script_dev.txt` Bash script. This script appears to be designed for monitoring and validating a Cerner Millennium environment, performing various system and domain health checks, logging results, and generating a JSON report. It uses tools like `jq`, `scpview`, `cclora`, and others to gather system information and check the status of services, processes, and resources. Below, I’ll break down the script comprehensively, explaining each section and line.

---

### **Header and Initial Setup**

```bash
#!/bin/bash
```

- **Line 1**: Declares the script as a Bash script, specifying that it should be executed using the Bash shell.

```bash
# Set the TERM
export TERM=xterm
```

- **Line 3-4**: Sets the `TERM` environment variable to `xterm`. This ensures consistent terminal behavior, especially for commands that rely on terminal formatting (e.g., color output).

```bash
# Get the current hostname
declare current_node=`hostname`
```

- **Line 6-7**: Declares a variable `current_node` and assigns it the hostname of the machine running the script, obtained via the `hostname` command. The backticks (`) are used for command substitution.

```bash
# Global variables
declare mill_env=$(echo $2 | tr '[:upper:]' '[:lower:]')
declare mill_user=""
declare mill_password=""
declare db_host=""
declare mpage_url=""
declare LOGDIR="/tmp"
declare LOGFILE="$LOGDIR/train_domain_checks_$(date '+%Y-%m-%d_%H-%M-%S').out"
declare USER=$(whoami)
declare SCRIPT_PATH=$(realpath $0)
declare PID=$$
declare checkTrnrfsh_flag="0"
declare -A scp_details
```

- **Line 9-20**: Defines global variables used throughout the script:
  - `mill_env`: Converts the second command-line argument (`$2`) to lowercase using `tr`. This is expected to be the Millennium environment name (e.g., "cert").
  - `mill_user` and `mill_password`: Initialize empty variables to store Millennium credentials.
  - `db_host`: Stores the database hostname, initially empty.
  - `mpage_url`: Stores the URL for the Millennium mPage, initially empty.
  - `LOGDIR`: Sets the directory for log files to `/tmp`.
  - `LOGFILE`: Defines the log file path with a timestamp (e.g., `/tmp/train_domain_checks_2025-06-03_10-18-00.out`).
  - `USER`: Stores the current user running the script using `whoami`.
  - `SCRIPT_PATH`: Stores the absolute path of the script using `realpath $0`.
  - `PID`: Stores the process ID of the script using `$$`.
  - `checkTrnrfsh_flag`: A flag to track whether the `checkTrnrfsh` function has been called, initialized to `0`.
  - `scp_details`: Declares an associative array to store SCP (Server Control Process) details.

```bash
# Set colors
Red='\033[1;31m'         # Red
Green='\033[1;32m'       # Green
Yellow='\033[1;33m'      # Yellow
Blue='\033[1;34m'        # Blue
CYAN='\033[1;36m'        # Cyan
NC='\033[0m'             # No Color
```

- **Line 22-29**: Defines ANSI color codes for formatting console output:
  - `Red`, `Green`, `Yellow`, `Blue`, `CYAN`: Bold colors for error, success, warning, info, and cyan messages.
  - `NC`: Resets color to default (no color).

---

### **Custom Logging Function**

```bash
# Custom logging function
echo_log() {

    if [[ "$1" == "-silent" ]]; then
        local message="$2"
        local log_level="${3:-INFO}"
    else
        local message="$1"
        local log_level="${2:-INFO}"
        echo -e "$message"
    fi

    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    # Remove color formatting and newline characters before logging
    local clean_message=$(echo -e "$message" | sed -E 's/\x1B\[[0-9;]*m//g')
    clean_message="${clean_message//$'\n'/}"
    
    # Log the message to the log file
    echo "$timestamp [$log_level] $clean_message" >> "$LOGFILE"

}
```

- **Line 31-48**: Defines the `echo_log` function for logging messages to both the console and the log file:
  - **Line 33-39**: Checks if the first argument is `-silent`. If true, the message is not printed to the console (`$2` is the message, `$3` is the log level, defaulting to `INFO`). Otherwise, the message (`$1`) is printed to the console using `echo -e`, and the log level (`$2`) defaults to `INFO`.
  - **Line 41**: Generates a timestamp in the format `YYYY-MM-DD HH:MM:SS`.
  - **Line 44**: Strips ANSI color codes from the message using `sed` to ensure clean text in the log file.
  - **Line 45**: Removes newline characters from the message to log it as a single line.
  - **Line 47**: Appends the timestamp, log level, and cleaned message to the `LOGFILE`.

---

### **Log File Management**

```bash
# Keep only the last two log files
ls -t $LOGDIR/train_domain_checks_*.out 2> /dev/null | tail -n +3 | xargs rm -f
```

- **Line 50-51**: Lists log files in `LOGDIR` matching `train_domain_checks_*.out`, sorted by modification time (`-t`). `tail -n +3` skips the two most recent files, and `xargs rm -f` deletes older files to keep only the latest two.

```bash
# Write a detailed header at the start of the log file
echo "======================================================" >> "$LOGFILE"
echo "Execution started on: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOGFILE"
echo "Host: $current_node" >> "$LOGFILE"
echo "User: $USER" >> "$LOGFILE"
echo "Script Path: $SCRIPT_PATH" >> "$LOGFILE"
echo "Process ID (PID): $PID" >> "$LOGFILE"
echo "======================================================" >> "$LOGFILE"
```

- **Line 53-60**: Writes a header to the log file, including a separator, execution start time, hostname, user, script path, and process ID.

```bash
# Print a execution start message.
echo_log "${Blue}\nScript Execution started...${NC}\n"
```

- **Line 62-63**: Logs and prints a message indicating the script has started, using blue text for the console output.

---

### **Usage Function**

```bash
# Function to display usage
usage() {
    echo_log "Usage: $0 -env <environment_name>"
    echo -e 
    echo_log "OPTIONS:"
    echo_log "  -env <environment_name>   Millennium environment name, Ex: cert"
    echo_log "  -h, --help                It will display the script usage"
    exit 1
}
```

- **Line 65-73**: Defines the `usage` function to display help information:
  - Logs and prints the correct usage syntax (`script.sh -env <environment_name>`).
  - Lists options: `-env` for specifying the environment name and `-h/--help` for displaying usage.
  - Exits with status code `1` (indicating an error).

---

### **Initial Validation Checks**

```bash
# Check if the script is being executed as "root"
if [[ $EUID -ne 0 ]]; then
    echo_log "${Red}Error:${NC} This script must be run as root. \nExiting." "ERROR"
    usage
fi
```

- **Line 75-79**: Checks if the script is running as root by testing the effective user ID (`$EUID`). If not `0` (root), it logs an error and calls `usage`, then exits.

```bash
# Check for help option
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    usage
fi
```

- **Line 81-84**: Checks if the first argument is `-h` or `--help`. If so, it calls `usage` and exits.

```bash
# Check for -env flag and if the environment name is provided
if [[ "$1" != "-env" || -z "$2" ]]; then
    echo_log "${Red}Error:${NC} Missing or incorrect argument." "ERROR"
    usage
fi
```

- **Line 86-90**: Ensures the first argument is `-env` and the second argument (environment name) is provided. If not, it logs an error and calls `usage`.

```bash
# Check for more than the required number of arguments
if [[ $# -gt 2 ]]; then
    echo_log "${Red}Error:${NC} Too many arguments." "ERROR"
    usage
fi
```

- **Line 92-96**: Checks if more than two arguments are provided. If so, it logs an error and calls `usage`.

---

### **JSON Template**

```bash
# Storing a default json template to track the status of the checks
defaultJson='{
    "hostname": null,
    "environment": null,
    "date": null,
    "logfile": null,
    "remoteFileName": null,
    "blockers": {
        "maintenance": {
            "status": null,
            "comment": null,
            "taskCategory": null,
            "maintenanceScope": null,
            "domainName": null,
            "associateName": null,
            "teamName": null,
            "eta": null
        },
        "trnrfsh": {
            "status": null,
            "comment": null
        }
    },
    "prerequisites": {
        "validDomain": {
            "status": null,
            "comment": null
        },
        "sourceEnv": {
            "status": null,
            "comment": null
        },
        "getCredentials": {
            "status": null,
            "comment": null
        },
        "jqInstalled": {
            "status": null,
            "comment": null
        }
    },
    "generalInfo": {
        "nodeUptime": {
            "value": null,
            "comment": null
        },
        "osVersion": {
            "value": null,
            "comment": null
        },
        "javaVersion": {
            "value": null,
            "comment": null
        },
        "mqVersion": {
            "value": null,
            "comment": null
        },
        "systemType": {
            "value": null,
            "comment": null
        },
        "iloAddress": {
            "value": null,
            "comment": null        
        }
    },
    "checks": {
        "checkRegistry": {
            "status": null,
            "comment": null
        },
        "checkMq": {
            "status": null,
            "comment": null
        },
        "checkTestsec": {
            "status": null,
            "comment": null
        },
        "checkScp": {
            "status": null,
            "comment": null,
            "deadScpList": null
        },
        "checkCcl": {
            "status": null,
            "comment": null
        },
        "checkMpage": {
            "status": null,
            "comment": null
        },
        "checkSystest": {
            "status": null,
            "comment": null
        },
        "checkCpu": {
            "appNode": {
                "name": null,
                "status": null,
                "processes": null,
                "recommendations": null,
                "comment": null
            },
            "dbNode": {
                "name": null,
                "status": null,
                "comment": null
            }
        },
        "checkMemory": {
            "appNode": {
                "name": null,
                "status": null,
                "processes": null,
                "recommendations": null,
                "comment": null
            },
            "dbNode": {
                "name": null,
                "status": null,
                "comment": null
            }
        },
        "checkCitrix": {
            "status": null,
            "comment": null
        },
        "checkTrnrfsh": {
            "status": null,
            "comment": null,
            "cronschedule": null,
            "timezone": null,
            "snapshot_date": null,
            "emailrecipients": null,
            "logfile": null,
            "logstate": null,
            "trnrfshlogtail": null
        }
    }
}'
```

- **Line 98-195**: Defines a JSON template (`defaultJson`) to store the results of various checks. The structure includes:
  - **Top-level fields**: `hostname`, `environment`, `date`, `logfile`, `remoteFileName`.
  - **blockers**: Tracks maintenance and `trnrfsh` (train domain refresh) job statuses.
  - **prerequisites**: Checks for valid domain, environment file sourcing, credentials, and `jq` installation.
  - **generalInfo**: Stores system details like uptime, OS version, Java version, MQ version, system type, and iLO address.
  - **checks**: Contains results of various health checks (e.g., registry, MQ, testsec, SCP, CCL, mPage, systest, CPU, memory, Citrix, and `trnrfsh`).

---

### **Cleanup Function**

```bash
cleanupFiles() {

    echo_log -silent "Cleanup all the temporary and json files from previous executions." "INFO"

    # If the output json file already exists from previous executions, delete it
    if [[ -f "/tmp/train_domain_checks_${current_node}_${mill_env}.json" ]]; then
        `rm -f /tmp/train_domain_checks_${current_node}_${mill_env}.json`
    fi

    # Cleanup all the temporary files from previous executions
    rm -f /tmp/deadservers.out
    rm -f /tmp/dbname.out
    rm -f /tmp/dbstatus.out
    rm -f /tmp/db_hostname.out
    rm -f /tmp/systest.out
    rm -f /tmp/ddirdump.out
    rm -f /tmp/mpage_url.out
    rm -f /tmp/get_scp_details.out

    return 0

}
```

- **Line 197-215**: Defines the `cleanupFiles` function to remove temporary and JSON files from previous script runs:
  - **Line 199**: Logs the cleanup action silently.
  - **Line 202-204**: Checks if a JSON file from a previous run exists and deletes it.
  - **Line 207-213**: Deletes temporary files used by various checks (e.g., `deadservers.out`, `dbname.out`).
  - **Line 215**: Returns `0` to indicate success.

---

### **JSON Update Function**

```bash
# Function to update a specific key in the JSON
updateJson() {
    local parent_element="$1"
    local child_element="$2"
    local key="$3"
    local value="$4"
    local nodeType="$5"  # Optional, can be "appNode" or "dbNode"

    if [ -z "$child_element" ]; then
        # Update a top-level element
        updatedJson=$(echo "$updatedJson" | jq --arg value "$value" --arg key "$key" '
            .[$key] = $value
        ')
    else
        if [ -z "$nodeType" ]; then
            # Update a regular nested element
            updatedJson=$(echo "$updatedJson" | jq --arg value "$value" --arg parent_element "$parent_element" --arg child_element "$child_element" --arg key "$key" '
                .[$parent_element][$child_element][$key] = $value
            ')
        else
            # Update appNode or dbNode specifically
            updatedJson=$(echo "$updatedJson" | jq --arg value "$value" --arg parent_element "$parent_element" --arg child_element "$child_element" --arg key "$key" --arg nodeType "$nodeType" '
                .[$parent_element][$child_element][$nodeType][$key] = $value
            ')
        fi
    fi
}
```

- **Line 217-237**: Defines the `updateJson` function to modify the JSON structure (`updatedJson`):
  - **Line 219-223**: Accepts parameters for parent element, child element, key, value, and optional node type (`appNode` or `dbNode`).
  - **Line 225-228**: If no `child_element` is provided, updates a top-level key in the JSON using `jq`.
  - **Line 230-234**: If `nodeType` is empty, updates a nested element under `parent_element` and `child_element`.
  - **Line 232-235**: If `nodeType` is provided, updates a nested element under `parent_element`, `child_element`, and `nodeType`.
  - **Line 237**: Closes the function.

---

### **JQ Installation Function**

```bash
# Function to install jq
install_jq() {
    echo_log -silent "JQ package installation (yum install -y jq) is started." "INFO"

    # Read the contents of /etc/system-release
    linux_os=$(cat /etc/system-release 2>/dev/null)

    # Check for Oracle Linux or RHEL
    if echo "$linux_os" | grep -i "oracle" > /dev/null || echo "$linux_os" | grep -i "red hat" > /dev/null; then
        # Declare the repo name containing jq package
        REPO_NAME="ol7_x86_64_addons"

        # Check if the repository is enabled
        if [ `yum repolist all | grep -i ol7_x86_64_addons | grep -i enabled | wc -l` -eq 1 ]; then
            
            echo_log -silent "Repository $REPO_NAME is enabled." "INFO"
	        
            # Install the jq package
            echo_log -silent "Installing JQ package..." "INFO"
	        yum install -y jq > /dev/null

            if command -v jq >/dev/null 2>&1; then
                echo_log "jq package installed successfully."
                updateJson "prerequisites" "jqInstalled" "status" "Passed"
                updateJson "prerequisites" "jqInstalled" "comment" "jq package installed successfully."
            else
                echo_log "Unable to install jq package. \nExiting." "ERROR"
                echo -e "$defaultJson" > /tmp/train_domain_checks_${current_node}_${mill_env}.json
                exit 1
            fi

        else    
            echo_log -silent "Repository $REPO_NAME is not enabled." "INFO"

	        # Enable the repository once the install is completed
            echo_log -silent "Trying to enable the repository $REPO_NAME ." "INFO"
	        yum-config-manager --enable ol7_x86_64_addons > /dev/null
	
	        # Install the jq package
            echo_log -silent "Installing JQ package..." "INFO"
	        yum install -y jq > /dev/null

            if command -v jq >/dev/null 2>&1; then
                # Disable the repository once the install is completed
	            yum-config-manager --disable ol7_x86_64_addons > /dev/null
                echo_log "jq package installed successfully."
                updateJson "prerequisites" "jqInstalled" "status" "Passed"
                updateJson "prerequisites" "jqInstalled" "comment" "jq package installed successfully."
            else
                echo_log "Unable to install jq package. \nExiting." "ERROR"
                echo -e "$defaultJson" > /tmp/train_domain_checks_${current_node}_${mill_env}.json
                exit 1
            fi
        fi
    else
        echo_log "Unknown or unsupported Linux distribution." "ERROR"
        echo_log "Please install jq package manually." "ERROR"
        echo -e "$defaultJson" > /tmp/train_domain_checks_${current_node}_${mill_env}.json
        exit 1
    fi
    return 0
}
```

- **Line 239-293**: Defines the `install_jq` function to install the `jq` package, required for JSON manipulation:
  - **Line 241**: Logs the start of `jq` installation.
  - **Line 244**: Reads the OS version from `/etc/system-release`.
  - **Line 247-248**: Checks if the OS is Oracle Linux or Red Hat by grepping for "oracle" or "red hat".
  - **Line 250**: Defines the repository name (`ol7_x86_64_addons`) containing the `jq` package.
  - **Line 253-263**: If the repository is enabled, installs `jq` using `yum install -y jq`. Checks if `jq` is installed successfully and updates the JSON accordingly. Exits with error if installation fails.
  - **Line 265-283**: If the repository is not enabled, enables it using `yum-config-manager`, installs `jq`, disables the repository, and updates the JSON. Exits with error if installation fails.
  - **Line 285-289**: If the OS is unsupported, logs an error, writes the default JSON, and exits.
  - **Line 291**: Returns `0` for success.

---

### **Check JQ Installation**

```bash
# Function to check if jq is installed
check_jq_installed() {
  if command -v jq >/dev/null 2>&1; then
    echo_log -silent "jq package is already installed. Proceeding.." "INFO"
    updateJson "prerequisites" "jqInstalled" "status" "Passed"
    updateJson "prerequisites" "jqInstalled" "comment" "jq package is already installed."
  else
    echo_log "jq is not installed. Installing..." "WARN"
    install_jq
  fi
}
```

- **Line 295-305**: Defines the `check_jq_installed` function:
  - **Line 297-300**: Checks if `jq` is installed using `command -v jq`. If present, logs success and updates the JSON.
  - **Line 302-303**: If `jq` is not installed, logs a warning and calls `install_jq`.

---

### **Initialize JSON**

```bash
# Initialize updatedJson with default JSON
updatedJson="$defaultJson"
```

- **Line 307-308**: Initializes the `updatedJson` variable with the `defaultJson` template for storing check results.

---

### **Maintenance State Check**

```bash
maintenanceState(){
    echo_log -silent "Checking /etc/motd to identify any maintenance events that are in progress" "INFO"

    local motdMaintCount=`grep -E 'Task Category|Associate Name' /etc/motd /etc/profile.d/custom_banner.sh 2> /dev/null | wc -l`
    
    if [[ $motdMaintCount -eq 0 ]]; then
        echo_log -silent "No maintenance events were found. Proceeding..." "INFO"
        updateJson "blockers" "maintenance" "status" "Passed"
        updateJson "blockers" "maintenance" "comment" "Maintenance events were not found."
        return 0
    else
        local activity_scope_ohat=$(grep "Maintenance Scope:" /etc/motd | cut -d ':' -f2 | xargs)
        local activity_scope_ohrr=$(grep "Maintenance Scope:" /etc/profile.d/custom_banner.sh 2> /dev/null | cut -d ':' -f2 | sed 's/,$//' | xargs)

        if [[ "${activity_scope_ohat,,}" == *"domain"* || "${activity_scope_ohrr,,}" == *"domain"* ]]; then
            local activity_domain_ohat=$(grep "Domain Name:" /etc/motd | cut -d ':' -f2 | xargs)
            local activity_domain_ohrr=$(grep "Domain Name:" /etc/profile.d/custom_banner.sh 2> /dev/null | cut -d ':' -f2 | sed 's/,$//' | xargs)
            if [[ "${activity_domain_ohat,,}" == *"${mill_env,,}"* ||  "${activity_domain_ohrr,,}" == *"${mill_env,,}"* ]]; then
                echo_log -silent "Domain maintenance events found for $mill_env" "ERROR"
            else
                echo_log -silent "The identified maintenance events are not related to domain $mill_env" "INFO"
                echo_log -silent "Proceeding..." "INFO"
                updateJson "blockers" "maintenance" "status" "Passed"
                updateJson "blockers" "maintenance" "comment" "Maintenance events were not found for $mill_env."
                return 0
            fi
        else
            echo_log -silent "Server maintenance events found for $mill_env" "ERROR"
        fi

        #invoke checkTrnrfsh method regardless of maintenance state
        checkTrnrfsh

        echo_log "||${Yellow} Abort  :${NC} A maintenance event for $mill_env domain is underway." "ERROR"
        echo_log "||${Yellow} Abort  :${NC} Millennium domain health checks will not be performed." "ERROR"
        echo_log "||${Yellow} Abort  :${NC} Please retry after maintenance event is completed." "ERROR"

        if [[ -e "/etc/profile.d/custom_banner.sh" && `grep -E 'Task Category|Associate Name' /etc/motd` ]]; then
            local task_category=$(grep "Task Category:" /etc/motd | cut -d ':' -f2 | xargs)
            local maintenance_scope=$(grep "Maintenance Scope:" /etc/motd | cut -d ':' -f2 | xargs)
            local domain_name=$(grep "Domain Name:" /etc/motd | cut -d ':' -f2 | xargs)
            local associate_name=$(grep "Associate Name:" /etc/motd | cut -d ':' -f2 | xargs)
            local team_name=$(grep "Team Name:" /etc/motd | cut -d ':' -f2 | xargs)
            local expected_completion=$(grep "Expected Completion of Maintenance:" /etc/motd | cut -d ':' -f2 | xargs)
        elif [[ -e "/etc/profile.d/custom_banner.sh" ]]; then
            local task_category=$(grep "Task Category:" /etc/profile.d/custom_banner.sh | cut -d ':' -f2 | sed 's/,$//' | xargs)
            local maintenance_scope=$(grep "Maintenance Scope:" /etc/profile.d/custom_banner.sh | cut -d ':' -f2 | sed 's/,$//' | xargs)
            local domain_name=$(grep "Domain Name:" /etc/profile.d/custom_banner.sh | cut -d ':' -f2 | sed 's/,$//' | xargs)
            local associate_name=$(grep "Associate Name:" /etc/profile.d/custom_banner.sh | cut -d ':' -f2 | sed 's/,$//' | xargs)
            local team_name=$(grep "Team Name:" /etc/profile.d/custom_banner.sh | cut -d ':' -f2 | sed 's/,$//' | xargs)
            local expected_completion=$(grep "Expected Completion of Maintenance:" /etc/profile.d/custom_banner.sh | sed 's/[^[:alnum:] :\/]//g' | sed -E 's/.*Expected Completion of Maintenance: (.*),?$/\1/'| xargs)
        elif [[ `grep -E 'Task Category|Associate Name' /etc/motd` ]]; then
            local task_category=$(grep "Task Category:" /etc/motd | cut -d ':' -f2 | xargs)
            local maintenance_scope=$(grep "Maintenance Scope:" /etc/motd | cut -d ':' -f2 | xargs)
            local domain_name=$(grep "Domain Name:" /etc/motd | cut -d ':' -f2 | xargs)
            local associate_name=$(grep "Associate Name:" /etc/motd | cut -d ':' -f2 | xargs)
            local team_name=$(grep "Team Name:" /etc/motd | cut -d ':' -f2 | xargs)
            local expected_completion=$(grep "Expected Completion of Maintenance:" /etc/motd | cut -d ':' -f2 | xargs)
        fi
        
        updateJson "blockers" "maintenance" "status" "Failed"
        updateJson "blockers" "maintenance" "comment" "Maintenance in-progress"
        updateJson "blockers" "maintenance" "taskCategory" "${task_category}"
        updateJson "blockers" "maintenance" "maintenanceScope" "${maintenance_scope}"
        updateJson "blockers" "maintenance" "domainName" "${domain_name}"
        updateJson "blockers" "maintenance" "associateName" "${associate_name}"
        updateJson "blockers" "maintenance" "teamName" "${team_name}"
        updateJson "blockers" "maintenance" "eta" "${expected_completion}"

        # Generate JSON file
        echo "$updatedJson" > "/tmp/train_domain_checks_${current_node}_${mill_env}.json"
        echo_log "\n||${CYAN} Info   :${NC} Generated json file /tmp/train_domain_checks_${current_node}_${mill_env}.json"
        echo_log "||${CYAN} Info   :${NC} Generated log file $LOGFILE"

        echo_log "\nExiting..." "ERROR"
            
        # Print a execution completion message.
        echo_log "${Blue}\nScript Execution Completed.${NC}\n"

        exit 0
    fi

}
```

- **Line 310-374**: Defines the `maintenanceState` function to check for ongoing maintenance events:
  - **Line 312**: Logs the start of the maintenance check.
  - **Line 314**: Counts lines in `/etc/motd` or `/etc/profile.d/custom_banner.sh` containing "Task Category" or "Associate Name" to detect maintenance events.
  - **Line 316-320**: If no maintenance events are found, logs success, updates JSON, and returns `0`.
  - **Line 322-328**: Extracts maintenance scope from `/etc/motd` and `custom_banner.sh`.
  - **Line 330-338**: If the scope includes "domain" and matches `mill_env`, logs an error. Otherwise, logs that the maintenance is unrelated and proceeds.
  - **Line 340**: If maintenance is server-related, logs an error.
  - **Line 343**: Calls `checkTrnrfsh` regardless of maintenance state.
  - **Line 345-347**: Logs an abort message if maintenance is ongoing for `mill_env`.
  - **Line 349-365**: Extracts maintenance details (task category, scope, domain, associate, team, ETA) from either `/etc/motd` or `custom_banner.sh`.
  - **Line 367-374**: Updates JSON with maintenance details, writes the JSON file, logs the file paths, and exits.

---

### **Cronjob State Check**

```bash
cronjobState() {
    echo_log -silent "Checking crontab to see if there are any trnrfsh jobs are scheduled and are running." "INFO"

    local cronjobCount=`crontab -l | grep -i $mill_env | grep -E -wi 'trnrfsh|crontab_master.ksh' | grep -v '^#' | grep -v 'l2_validation.ksh' | wc -l`
    local cronjobProcCount=""
    local cronjobProcId=""

    if [[ $cronjobCount -eq 1 ]]; then
        
        echo_log -silent "Scheduled trnrfsh jobs were found." "INFO"

        cronjobProcCount=`ps -ef | grep $mill_env | grep -E -wi 'trnrfsh|crontab_master.ksh' | wc -l`
        cronjobProcId=`ps -ef | grep $mill_env | grep -E -wi 'trnrfsh|crontab_master.ksh' | awk '{print $2}'`

        if [[ $cronjobProcCount -gt 0 ]]; then
            
            #invoke checkTrnrfsh method even if trnrfsh job is running.
            checkTrnrfsh

            echo_log "||${Yellow} Abort  :${NC} Scheduled trnrfsh job for $mill_env domain is currently running." "ERROR"
            echo_log "||${Yellow} Abort  :${NC} Millennium domain health checks will not be performed." "ERROR"
            echo_log "||${Yellow} Abort  :${NC} Please retry after trnrfsh job is completed." "ERROR"

            updateJson "blockers" "trnrfsh" "status" "Failed"
            updateJson "blockers" "trnrfsh" "comment" "Scheduled trnrfsh job is running."

            # Generate JSON file
            echo "$updatedJson" > "/tmp/train_domain_checks_${current_node}_${mill_env}.json"
            echo_log "\n||${CYAN} Info   :${NC} Generated json file /tmp/train_domain_checks_${current_node}_${mill_env}.json"
            echo_log "||${CYAN} Info   :${NC} Generated log file $LOGFILE"

            echo_log "\nExiting..." "ERROR"
            
            # Print a execution completion message.
            echo_log "${Blue}\nScript Execution Completed.${NC}\n"

            exit 0            
        else
            echo_log -silent "Scheduled trnrfsh job for $mill_env domain is not running. Proceeding..." "INFO"
            updateJson "blockers" "trnrfsh" "status" "Passed"
            updateJson "blockers" "trnrfsh" "comment" "Scheduled trnrfsh job is not running."
            return 0
        fi
    else
        echo_log -silent "No scheduled trnrfsh jobs were found. Proceeding..." "INFO"
        updateJson "blockers" "trnrfsh" "status" "Passed"
        updateJson "blockers" "trnrfsh" "comment" "Scheduled trnrfsh jobs were not found."
        return 0
    fi
}
```

- **Line 376-418**: Defines the `cronjobState` function to check for running `trnrfsh` jobs:
  - **Line 378**: Logs the start of the cronjob check.
  - **Line 380**: Counts active `trnrfsh` or `crontab_master.ksh` jobs for `mill_env` in the crontab.
  - **Line 382-383**: Initializes variables for process count and ID.
  - **Line 385-397**: If one job is found, checks if it’s running using `ps -ef`. If running, calls `checkTrnrfsh`, logs an abort message, updates JSON, writes the JSON file, and exits.
  - **Line 399-403**: If the job is not running, logs success, updates JSON, and returns `0`.
  - **Line 405-409**: If no jobs are found, logs success, updates JSON, and returns `0`.

---

### **Environment Validation**

```bash
# Validate the input environment for its existance
envValidation() {
    echo_log -silent "Validating the input environment($1) for its existance." "INFO"

    local env="$1"
    local valid_env=0

    # Check if arguments are provided
    if [[ -z "$env" ]]; then
        echo_log "${Red}Error:${NC} Missing arguments." "ERROR"
        echo_log "Usage: checkMQ <environment_name>"
        return 1
    fi

    # Define the millennium common environment file path
    env_file_path="/cerner/mgr/common_environment.ksh"
    env_file_name="common_environment.ksh"

    # Check if the millennium common environment file exists
    if [[ -e "$env_file_path" ]]; then
        # Source the millennium common environment file
        source "$env_file_path"
        echo_log -silent "||${Green} Success:${NC} Sourced common environment file: $env_file_name" "INFO"
    else
        echo_log "||${Red} Failed :${NC} Common environment file '$env_file_path' does not exist \nExiting." "ERROR"
        updateJson "prerequisites" "validDomain" "status" "Failed"
        updateJson "prerequisites" "validDomain" "comment" "Common environment file '$env_file_path' does not exist \nExiting."
        exit 1
    fi

    # Get domains registered to current node
    echo_log -silent "Get domains registered to current node from ddirdump" "INFO"
    ddirdump -domainsbynode $current_node > /tmp/ddirdump.out 2> /dev/null

    status_code=$?

    # Check if ddirdump results were captured in the temp file
    if [ $status_code -eq 0 ] && [ -e "/tmp/ddirdump.out" ]; then
        echo_log -silent "||${Green} Success:${NC} Retreived results from ddirdump" "INFO"
    else
        echo_log "||${Red} Failed :${NC} Unable to retreive results from ddirdump" "ERROR"
        echo_log "||${Red} Failed :${NC} Unable to check if the provided environment was valid or not[2]" "ERROR"
        echo_log "Exiting.\n" "ERROR"
        updateJson "prerequisites" "validDomain" "status" "Failed"
        updateJson "prerequisites" "validDomain" "comment" "Unable to check if the provided environment was valid or not[2]"
        exit 1
    fi

    # Filter the domain names
    domains=`sed -e "1,/$current_node/ d" /tmp/ddirdump.out | awk '{print $2}'`
    
    for domain in $domains
    do
        if [[ "$domain" == "$env" ]]; then
            valid_env=1
        fi
    done

    if [[ "$valid_env" == "0" ]]; then
        echo_log "||${Red} Failed :${NC} Provided environment $env is not found on $current_node" "ERROR"
        echo_log "Exiting."
        updateJson "prerequisites" "validDomain" "status" "Failed"
        updateJson "prerequisites" "validDomain" "comment" "Provided environment $env is not found on $current_node"
        exit 1
    else
        echo_log "||${Green} Success:${NC} Provided environment $env is found on $current_node" "INFO"
        updateJson "prerequisites" "validDomain" "status" "Passed"
        updateJson "prerequisites" "validDomain" "comment" "Provided environment $env is found on $current_node"
        return 0
    fi

    return 0
}
```

- **Line 420-474**: Defines the `envValidation` function to validate the input environment:
  - **Line 422**: Logs the validation start.
  - **Line 424-425**: Stores the input environment and initializes a flag.
  - **Line 428-431**: Checks if an environment is provided, logs an error if not.
  - **Line 434-435**: Defines the path to the common environment file.
  - **Line 438-444**: Sources the file if it exists, logs success; otherwise, logs an error, updates JSON, and exits.
  - **Line 447-453**: Runs `ddirdump` to get domains registered to the node, checks if results are captured.
  - **Line 456**: Filters domain names from the output.
  - **Line 458-462**: Checks if the input environment matches any domain.
  - **Line 464-474**: Logs success or failure, updates JSON, and exits if the environment is invalid.

---

### **Environment File Check**

```bash
envFileCheck() {
    local env="$1"

    echo_log -silent "Verify if /cerner/mgr/${env}_environment.ksh exists." "INFO"

    # Define the millennium environment file path
    env_file_path="/cerner/mgr/${env}_environment.ksh"

    # Check if the millennium environment file exists and is not empty
    if [[ -f "$env_file_path" && -s "$env_file_path" ]]; then
        return 0
    else
        return 1
    fi
}
```

- **Line 476-488**: Defines the `envFileCheck` function to verify the existence of an environment-specific file:
  - **Line 480**: Logs the check.
  - **Line 483**: Constructs the file path.
  - **Line 486-488**: Returns `0` if the file exists and is non-empty, else `1`.

---

### **Set Millennium Credentials**

```bash
# Set millennium username and password
setMillUserPass() {
    echo_log -silent "Retreive millennium username and password from lregview." "INFO"

    local status_code=""

    mill_user=$($cer_exe/lreg -getp \\\\Node\\\\${current_node}\\\\Domain\\\\${mill_env} LogonUser 2>/dev/null)
    status_code=$?
    # Check if the millennium user was retreived successfully
    if [ $status_code -ne 0 ]; then
        echo_log "||${Red} Failed :${NC} Millennium username retreive failed. \nExiting." "ERROR"
        updateJson "prerequisites" "getCredentials" "status" "Failed"
        updateJson "prerequisites" "getCredentials" "comment" "Millennium username retreive failed."
        exit $status_code
    fi

    mill_password=$($cer_exe/lreg -getp \\\\Node\\\\${current_node}\\\\Domain\\\\${mill_env} LogonPassword 2>/dev/null)
    status_code=$?
    # Check if the millennium password was retreived successfully
    if [ $status_code -ne 0 ]; then
        echo_log "||${Red} Failed :${NC} Millennium ${mill_user} user password retreive failed. \nExiting." "ERROR"
        updateJson "prerequisites" "getCredentials" "status" "Failed"
        updateJson "prerequisites" "getCredentials" "comment" "Millennium ${mill_user} user password retreive failed."
        exit $status_code
    fi

    echo_log "||${Green} Success:${NC} Millennium user credentials retreived successfully" "INFO"
    updateJson "prerequisites" "getCredentials" "status" "Passed"
    updateJson "prerequisites" "getCredentials" "comment" "Millennium user credentials retreived successfully."

    return 0
}
```

- **Line 490-515**: Defines the `setMillUserPass` function to retrieve Millennium credentials:
  - **Line 492**: Logs the credential retrieval.
  - **Line 494-500**: Retrieves the username using `lreg`, checks the status, and exits if it fails.
  - **Line 502-508**: Retrieves the password, checks the status, and exits if it fails.
  - **Line 510-513**: Logs success and updates JSON.
  - **Line 515**: Returns `0`.

---

### **General System Info**

```bash
# This function will gather all the general system info or software version info
generalInfo() {
    local nodeuptime=`uptime 2> /dev/null | awk '{gsub(/,/, "", $4); print $3, $4}'`
    local osver=`cat /etc/system-release`
    local javaver=`java -version 2>&1 | head -n 1 | awk -F '"' '{print $2}'`
    local mqver=`dspmqver 2> /dev/null | grep -i version | awk -F " " '{print $2}'`
    local systype=`if dmidecode -s system-manufacturer 2>/dev/null | grep -q VMware; then echo "Virtual"; elif virt-what 2>/dev/null | grep -q vmware; then echo "Virtual"; else echo "Physical"; fi`
    local ilo="NA"

    if command -v ipmitool &>/dev/null; then
        ilo=`ipmitool lan print 2>/dev/null | grep "IP Address" | grep -v "IP Address Source" |awk '{print "https://"$4}'`
    else
        ilo="NA"
    fi

    updateJson "generalInfo" "nodeUptime" "value" "${nodeuptime}"
    updateJson "generalInfo" "osVersion" "value" "${osver}"
    updateJson "generalInfo" "javaVersion" "value" "${javaver}"
    updateJson "generalInfo" "mqVersion" "value" "${mqver}"
    updateJson "generalInfo" "systemType" "value" "${systype}"
    updateJson "generalInfo" "iloAddress" "value" "${ilo}"
}
```

- **Line 517-535**: Defines the `generalInfo` function to collect system information:
  - **Line 519**: Gets system uptime.
  - **Line 520**: Reads OS version from `/etc/system-release`.
  - **Line 521**: Gets Java version.
  - **Line 522**: Gets IBM MQ version.
  - **Line 523**: Determines if the system is virtual or physical.
  - **Line 524-529**: Gets the iLO address if `ipmitool` is available, else sets to "NA".
  - **Line 531-535**: Updates JSON with the collected information.

---

### **Registry Server Check**

```bash
# Check if cerner registry server is running
checkRegistry() {
    echo_log -silent "Checking if cerner registry server is running." "INFO"

    if [ `ps -ef | grep -i reg_server | grep -v grep | wc -l` -eq 2 ]; then
        echo_log "||${Green} Success:${NC} Registery server is running." "INFO"
        updateJson "checks" "checkRegistry" "status" "Passed"
        updateJson "checks" "checkRegistry" "comment" "Registry server is running"
        return 0
    else
        echo_log "||${Red} Failed :${NC} Registry server is not running." "ERROR"
        updateJson "checks" "checkRegistry" "status" "Failed"
        updateJson "checks" "checkRegistry" "comment" "Registry server is not running"
        return 1
    fi  
}
```

- **Line 537-550**: Defines the `checkRegistry` function to verify if the Cerner registry server is running:
  - **Line 539**: Logs the check.
  - **Line 541-544**: Checks if exactly two `reg_server` processes are running, logs success, and updates JSON.
  - **Line 546-549**: If not, logs failure and updates JSON.
  - **Line 550**: Returns `0` for success, `1` for failure.

---

### **IBM MQ Listener Check**

```bash
# Check if IBM MQ listener is running
checkMQ() {
    echo_log -silent "Checking if IBM MQ listener is running." "INFO"

    local env="$1"

    # Check if arguments are provided
    if [[ -z "$env" ]]; then
        echo_log "${Red}Error:${NC} Missing arguments." "ERROR"
        echo_log "Usage: checkMQ <environment_name>"
        return 1
    fi

    if [ `ps -ef | grep -i runmqlsr | grep -iw ${env} | wc -l ` -eq 1 ]; then
        echo_log "||${Green} Success:${NC} IBM MQ listener for the domain ${env} is running." "INFO"
        updateJson "checks" "checkMq" "status" "Passed"
        updateJson "checks" "checkMq" "comment" "MQ listener is running"
        return 0
    else
        echo_log "||${Red} Failed :${NC} IBM MQ listener for the domain ${env} is not running." "ERROR"
        updateJson "checks" "checkMq" "status" "Failed"
        updateJson "checks" "checkMq" "comment" "MQ listener is not running"
        return 1
    fi
}
```

- **Line 552-571**: Defines the `checkMQ` function to check if the IBM MQ listener is running:
  - **Line 554**: Logs the check.
  - **Line 556**: Stores the environment name.
  - **Line 559-562**: Checks if an environment is provided.
  - **Line 564-567**: Checks if one `runmqlsr` process is running for the environment, logs success, and updates JSON.
  - **Line 569-571**: If not, logs failure and updates JSON.

---

### **Testsec Check**

```bash
# Check if testsec is working
checkTestsec() {
    echo_log -silent "Checking if testsec is working." "INFO"

    local env="$1"

     # Check if arguments are provided
    if [[ -z "$env" ]]; then
        echo_log "${Red}Error:${NC} Missing arguments." "ERROR"
        echo_log "Usage: checkTestsec <environment_name>"
        return 1
    fi

    local testsec_result=`testsec $mill_user $env $mill_password`

    if [ $(echo "$testsec_result" | grep -i "seq=" | grep -v grep | wc -l) -eq 10 ]; then
        avg_elapsed_time=$(echo "$testsec_result" | grep -A 1 "elapsed time (seconds)" | grep "average" | awk -F'= ' '{print $2}')
        echo_log "||${Green} Success:${NC} Testsec check  successful, avg elapsed time: $avg_elapsed_time sec." "INFO"
        updateJson "checks" "checkTestsec" "status" "Passed"
        updateJson "checks" "checkTestsec" "comment" "Testsec is working"
        return 0
    elif [ $(echo "$testsec_result" | grep -i "login failed" | grep -v grep | wc -l) -eq 1 ]; then
        echo_log "||${Red} Failed :${NC} The testsec check is failed." "ERROR"
        echo_log "$testsec_result" "ERROR"
        updateJson "checks" "checkTestsec" "status" "Failed"
        updateJson "checks" "checkTestsec" "comment" "Testsec is not working"
        return 1
    else
        echo_log "||${Red} Failed :${NC} The testsec check is failed." "ERROR"
        echo_log "$testsec_result" "ERROR"
        updateJson "checks" "checkTestsec" "status" "Failed"
        updateJson "checks" "checkTestsec" "comment" "Testsec is not working"
        return 1
    fi

    return 0
}
```

- **Line 573-601**: Defines the `checkTestsec` function to verify the `testsec` utility:
  - **Line 575**: Logs the check.
  - **Line 577**: Stores the environment name.
  - **Line 580-583**: Checks if an environment is provided.
  - **Line 585**: Runs `testsec` with credentials and environment.
  - **Line 587-591**: If 10 `seq=` lines are found, extracts the average elapsed time, logs success, and updates JSON.
  - **Line 592-596**: If a "login failed" message is found, logs failure and updates JSON.
  - **Line 597-601**: For other failures, logs the result and updates JSON.

---

### **Dead SCP Servers Check**

```bash
# Check if there are any dead servers in scpview
checkDeadScpServers() {
    echo_log -silent "Checking if there are any dead servers in scpview." "INFO"

    local env="$1"
    local dead_count=""
    local scp_error=""

     # Check if arguments are provided
    if [[ -z "$env" ]]; then
        echo_log "${Red}Error:${NC} Missing arguments." "ERROR"
        echo_log "Usage: checkDeadScpServers <environment_name> <target_hostname>"
        return 1
    fi
    
$cer_exe/scpview << EOF > "/tmp/deadservers.out"
${mill_user}
${env}
${mill_password}
select $current_node
dead
exit
EOF

    # Check if scpview results were captured in the temp file
    if [[ -e "/tmp/deadservers.out" ]]; then
        echo_log -silent "Retreived results from scpview." "INFO"
    else
        echo_log "||${Red} Failed :${NC} Unable to retreive results from scpview" "ERROR"
        updateJson "checks" "checkScp" "status" "Failed"
        updateJson "checks" "checkScp" "comment" "Unable to retreive results from scpview"
        return 1
    fi

    if [[ $(sed -n '/------------------/,$p' /tmp/deadservers.out | grep -E '^[0-9]+' | wc -l) -eq 0 && $(grep -i "Dead servers" /tmp/deadservers.out |wc -l) -eq 1 ]];then
        echo_log "||${Green} Success:${NC} No dead SCP servers were found." "INFO"
        updateJson "checks" "checkScp" "status" "Passed"
        updateJson "checks" "checkScp" "comment" "No dead SCP servers were found"
        return 0
    elif [[ $(grep -i "Dead servers" /tmp/deadservers.out |wc -l) -eq 0 ]]; then
        scp_error=`cat /tmp/deadservers.out`
        echo_log "||${Red} Failed :${NC} Unable to query scpview utility." "ERROR"
        updateJson "checks" "checkScp" "status" "Failed"
        updateJson "checks" "checkScp" "comment" "Unable to query scpview utility"
        echo $scp_error
        return 1
    else
        dead_count=`sed -n '/------------------/,$p' /tmp/deadservers.out | grep -E '^[0-9]+' | wc -l`
        dead_servers=`sed -n '/------------------/,$p' /tmp/deadservers.out | grep -E '^[0-9]+'`
        
        if [ $dead_count -le 5 ]; then
            echo_log "||${Yellow} Warning :${NC} ${dead_count} dead servers were found in SCP." "ERROR"
            updateJson "checks" "checkScp" "status" "Partial"
            updateJson "checks" "checkScp" "comment" "${dead_count} dead servers were found"
            updateJson "checks" "checkScp" "deadScpList" "${dead_servers}"
        else
            echo_log "||${Red} Failed :${NC} ${dead_count} dead servers were found in SCP." "ERROR"
            updateJson "checks" "checkScp" "status" "Failed"
            updateJson "checks" "checkScp" "comment" "${dead_count} dead servers were found"
            updateJson "checks" "checkScp" "deadScpList" "${dead_servers}"
        fi
        return 1
    fi

    return 0
}
```

- **Line 603-650**: Defines the `checkDeadScpServers` function to check for dead servers in `scpview`:
  - **Line 605**: Logs the check.
  - **Line 607-608**: Initializes variables.
  - **Line 611-614**: Checks if an environment is provided.
  - **Line 616-622**: Runs `scpview` to list dead servers, saving output to `deadservers.out`.
  - **Line 624-628**: Verifies if the output file exists.
  - **Line 630-634**: If no dead servers are found, logs success and updates JSON.
  - **Line 635-639**: If `scpview` fails, logs the error and updates JSON.
  - **Line 641-649**: If dead servers are found, logs a warning (if ≤5) or failure (>5), updates JSON with the count and list of dead servers.

---

### **CCL Check**

```bash
# Check for ccl working status
checkCCL() {
    echo_log -silent "Checking if ccl is working fine or not." "INFO"

    local env="$1"

    # Check if arguments are provided
    if [[ -z "$env" ]]; then
        echo_log "${Red}Error:${NC} Missing arguments." "ERROR"
        echo_log "Usage: checkCCL <environment_name>"
        return 1
    fi

$cer_exe/cclora << EOF > /dev/null
select into "/tmp/dbname.out" name from v\$database go
select into "/tmp/dbstatus.out" status from v\$instance go
select into "/tmp/db_hostname.out" host_name from v\$instance go
select into "/tmp/mpage_url.out" info_char from dm_info where info_name='CONTENT_SERVICE_URL' go
exit
EOF

    # Check if cclora results were captured in the temp file
    if [[ -e "/tmp/dbname.out" && -e "/tmp/dbstatus.out" && -e "/tmp/db_hostname.out" ]]; then
        echo_log -silent "Retreived results from cclora." "INFO"
    else
        echo_log "||${Red} Failed :${NC} Unable to retreive results from cclora" "ERROR"
        updateJson "checks" "checkCcl" "status" "Failed"
        updateJson "checks" "checkCcl" "comment" "Unable to retreive results from cclora"
        return 1
    fi

    DBMATCH=`cat /tmp/dbname.out | grep -i ${env} | wc -l`
    DBCHECK=`cat /tmp/dbstatus.out | grep OPEN | wc -l`

    if [[ $DBMATCH -ne 1 && $DBCHECK -lt 1 ]]; then
        echo_log "||${Red} Failed :${NC} There is not an open instance of the database or no matching ${env} database is retreived." "ERROR"
        updateJson "checks" "checkCcl" "status" "Failed"
        updateJson "checks" "checkCcl" "comment" "There is not an open instance of the database or no matching ${env} database is retreived"
        return 1
    else
        echo_log "||${Green} Success:${NC} CCL is functional." "INFO"
        updateJson "checks" "checkCcl" "status" "Passed"
        updateJson "checks" "checkCcl" "comment" "CCL is functional"
        
        db_hostname_out_path="/tmp/db_hostname.out"

        if [[ -s "$db_hostname_out_path" ]]; then
            fqdn=$(grep -v "HOST_NAME" "$db_hostname_out_path")
            if [[ -n "$fqdn" ]]; then
                db_host=$(echo "$fqdn" | cut -d '.' -f 1)
                echo "Fetched the database Hostname: $db_host" > /dev/null
            fi
        fi

        return 0
    fi

    return 0
}
```

- **Line 652-694**: Defines the `checkCCL` function to verify the CCL (Cerner Command Language) functionality:
  - **Line 654**: Logs the check.
  - **Line 656**: Stores the environment name.
  - **Line 659-662**: Checks if an environment is provided.
  - **Line 664-669**: Runs `cclora` to query database name, status, hostname, and mPage URL.
  - **Line 671-675**: Verifies if output files exist.
  - **Line 677-678**: Checks if the database name matches `env` and is open.
  - **Line 680-683**: If not, logs failure and updates JSON.
  - **Line 685-693**: If successful, logs success, updates JSON, and extracts the database hostname.

---

### **Systest Check**

```bash
# Check systest 1 - a near equivalent of hnatest.exe
checkSystest() {
    echo_log -silent "Checking systest 1 - a near equivalent of hnatest.exe on the application node." "INFO"

    local env="$1"
    local TIMEOUT_DURATION=15

    # Check if arguments are provided
    if [[ -z "$env" ]]; then
        echo_log "${Red}Error:${NC} Missing arguments." "ERROR"
        echo_log "Usage: checkDeadScpServers <environment_name>"
        return 1
    fi

timeout $TIMEOUT_DURATION $cer_exe/systest 1 << EOF > "/tmp/systest.out"
${mill_user}
${env}
${mill_password}
EOF

    # Check if systest results were captured in the temp file
    if [[ -e "/tmp/systest.out" ]]; then
        echo_log -silent "Retreived results from systest." "INFO"
    else
        echo_log "||${Red} Failed :${NC} Unable to retreive results from systest" "ERROR"
        updateJson "checks" "checkSystest" "status" "Failed"
        updateJson "checks" "checkSystest" "comment" "Unable to retreive results from systest"
        return 1
    fi

    local test_auth=`cat /tmp/systest.out | grep -i "The Authorization server test succeeded" | grep -v grep | wc -l`
    local test_tdb=`cat /tmp/systest.out | grep -i "TDB was successful in selecting message" | grep -v grep | wc -l`
    local test_scriptsrv=`cat /tmp/systest.out | grep -i "The Script server test succeeded" | grep -v grep | wc -l`
    local test_decoder=`cat /tmp/systest.out | grep -i "The Decoder server test succeeded" | grep -v grep | wc -l`
    local test_processsrv=`cat /tmp/systest.out | grep -i "The Process server test succeeded" | grep -v grep | wc -l`
    local test_systest=`cat /tmp/systest.out | grep -i "System testing completed" | grep -v grep | wc -l`

    if [[ $test_auth -eq 1 &&  $test_tdb -eq 1 && $test_scriptsrv -eq 1 && $test_decoder -eq 1 && $test_processsrv -eq 1 && $test_systest -eq 1 ]]; then
        echo_log "||${Green} Success:${NC} Systest successful." "INFO"
        updateJson "checks" "checkSystest" "status" "Passed"
        updateJson "checks" "checkSystest" "comment" "'systest 1' successful"
        return 0
    elif [[ $test_auth -eq 1 &&  $test_tdb -eq 1 && $test_scriptsrv -eq 1 && $test_decoder -eq 1 && $test_processsrv -ne 1 && $test_systest -eq 1 ]]; then
        echo_log "||${Green} Success:${NC} Systest successful." "INFO"
        updateJson "checks" "checkSystest" "status" "Passed"
        updateJson "checks" "checkSystest" "comment" "'systest 1' successful"
        return 0
    else
        echo_log "||${Red} Failed :${NC} Systest contains errors." "ERROR"
        updateJson "checks" "checkSystest" "status" "Failed"
        updateJson "checks" "checkSystest" "comment" "Systest contains errors"
        return 1
    fi
}
```

- **Line 696-736**: Defines the `checkSystest` function to run `systest 1`, similar to `hnatest.exe`:
  - **Line 698**: Logs the check.
  - **Line 700-701**: Stores the environment and sets a 15-second timeout.
  - **Line 704-707**: Checks if an environment is provided.
  - **Line 709-713**: Runs `systest` with a timeout, saving output to `systest.out`.
  - **Line 715-719**: Verifies if the output file exists.
  - **Line 721-726**: Checks for specific success messages in the output.
  - **Line 728-736**: Logs success if all tests pass or if only the process server test fails but others pass; otherwise, logs failure.

---

### **mPage URL Check**

```bash
# Check if mpage URL can be reached
checkMpage() {
    echo_log -silent "Checking if mpage URL can be reached from the application node." "INFO"

    # Check if mpage_url.out file is empty
    if [[ -e "/tmp/mpage_url.out" ]]; then
        echo_log -silent "The mpage URL is retreived from the database." "INFO"
        mpage_url=$(grep -Eo '(http|https)://[^ ]+' /tmp/mpage_url.out)
    else
        echo_log "||${Red} Failed :${NC} Unable to fetch the mpage url from the database." "ERROR"
        updateJson "checks" "checkMpage" "status" "Failed"
        updateJson "checks" "checkMpage" "comment" "Unable to fetch the mpage url from the database."
        return 1
    fi
    
    # Check if the mpage_url variable is empty
    if [ -z "$mpage_url" ]; then
        echo_log "||${Red} Failed :${NC} Mpage URL is not defined in the database." "ERROR"
        updateJson "checks" "checkMpage" "comment" "Mpage URL is not defined in the database."
        return 1
    else
        # Check if the Mpage URL is reachable
        if curl --output /dev/null --silent --head --fail "${mpage_url%/}/manager"; then
            echo_log "||${Green} Success:${NC} Mpage URL is reachable." "INFO"
            updateJson "checks" "checkMpage" "status" "Passed"
            updateJson "checks" "checkMpage" "comment" "Mpage URL is reachable."
            return 0
        else
            echo_log "||${Red} Failed :${NC} Unable to reach the Mpage URL." "ERROR"
            updateJson "checks" "checkMpage" "status" "Failed"
            updateJson "checks" "checkMpage" "comment" "Unable to reach the Mpage URL."
            return 1
        fi
    fi
    
}
```

- **Line 738-767**: Defines the `checkMpage` function to verify if the mPage URL is reachable:
  - **Line 740**: Logs the check.
  - **Line 742-747**: Checks if `mpage_url.out` exists and extracts the URL.
  - **Line 749-752**: If the URL is empty, logs failure and updates JSON.
  - **Line 754-767**: Uses `curl` to check if the URL is reachable, logs success or failure, and updates JSON.

---

### **SCP Entry Retrieval**

```bash
# This function will fetch the SCP entry when provided with millennium environment name and process ID
getScpEntryIdByPId (){
    
    `rm -f /tmp/get_scp_details.out`

    local env="$1"
    local command="$2"

    local millUser=""
    local millPassword=""
    local scp_env=""
    scp_entry_id=""
    scp_entry_name=""

    if [[ "$env" != "$mill_env" ]]; then
        millUser=$($cer_exe/lreg -getp \\\\Node\\\\${current_node}\\\\Domain\\\\${env} LogonUser)
        millPassword=$($cer_exe/lreg -getp \\\\Node\\\\${current_node}\\\\Domain\\\\${env} LogonPassword)
        scp_env=$env
    else
        millUser=$($cer_exe/lreg -getp \\\\Node\\\\${current_node}\\\\Domain\\\\${mill_env} LogonUser)
        millPassword=$($cer_exe/lreg -getp \\\\Node\\\\${current_node}\\\\Domain\\\\${mill_env} LogonPassword)
        scp_env=$mill_env
    fi

$cer_exe/scpview << EOF > "/tmp/get_scp_details.out"
${millUser}
${scp_env}
${millPassword}
select $current_node
$command
exit
EOF

    scp_entry_id=`cat /tmp/get_scp_details.out | grep -i "entry:" | awk -F" " '{print $2}'`
    scp_entry_name=`cat /tmp/get_scp_details.out | grep -i "description:" | awk -F":" '{print $2}' | sed 's/^ *//;s/ *$//'`

    scp_details["scp_id"]="$scp_entry_id"
    scp_details["scp_name"]="$scp_entry_name"
}
```

- **Line 769-797**: Defines the `getScpEntryIdByPId` function to retrieve SCP entry details:
  - **Line 771**: Removes any existing `get_scp_details.out`.
  - **Line 773-774**: Stores the environment and command.
  - **Line 776-779**: Initializes variables.
  - **Line 781-787**: Retrieves credentials for the specified environment or `mill_env`.
  - **Line 789-795**: Runs `scpview` to get SCP details.
  - **Line 797**: Stores the entry ID and name in the `scp_details` array.

---

### **High Memory Consumers**

```bash
# This function will fetch the top memory consumers on the node and sets the SCP entry ID
high_memory_consumers() {
    local pid mem user command scp_id scp_name extracted_env line
    local top_mem_processes=""

    # Add the header using printf directly to the variable
    printf -v top_mem_processes "%-8s %-12s %-8s %-12s %s\n" "PID" "MEMORY" "USER" "SCP-ID" "SCP-NAME"

    mapfile -t processes < <(ps aux --sort=-rss | head -10 | awk 'NR==1 {next} {printf "%s\t%s\t%s\t%s\n", $2, $6/1024 "MiB", $1, $11}')

    if [[ ${#processes[@]} -gt 0 ]]; then
        for process in "${processes[@]}"; do
            IFS=$'\t' read -r pid mem user command <<< "$process"

            if [[ "$user" != "root" ]]; then
                extracted_env=$(echo "$user" | cut -d '_' -f2)
                getScpEntryIdByPId "$extracted_env" "server -pid $pid"
                scp_id="${scp_details[scp_id]}"
                scp_name="${scp_details[scp_name]}"
            else
                if [[ "$command" == *"sentinel"* ]]; then
                    scp_id="sentinel"
                    scp_name="sentinel"
                else
                    scp_id="OSProcess"
                    scp_name="OSProcess"
                fi
            fi

            printf -v line "%-8s %-12s %-8s %-12s %s\n" "$pid" "$mem" "$user" "$scp_id" "$scp_name"
            top_mem_processes+="$line"

        done
    else
        top_mem_processes+="No processes found.\n"
    fi

    printf "%s" "$top_mem_processes"
}
```

- **Line 799-828**: Defines the `high_memory_consumers` function to list top memory-consuming processes:
  - **Line 801-802**: Initializes variables.
  - **Line 805**: Creates a header for the output.
  - **Line 807**: Gets the top 10 processes by memory usage.
  - **Line 809-824**: For each process, retrieves SCP details if the user isn’t root; otherwise, labels as `sentinel` or `OSProcess`.
  - **Line 826**: If no processes are found, adds a message.
  - **Line 828**: Outputs the formatted list.

---

### **High CPU Consumers**

```bash
# This function will fetch the top CPU consumers on the node and sets the SCP entry ID
high_cpu_consumers() {
    local pid cpu user command scp_id extracted_env line
    local top_cpu_processes=""

    # Add the header using printf directly to the variable
    printf -v top_cpu_processes "%-8s %-12s %-8s %-12s %s\n" "PID" "CPU%" "USER" "SCP-ID" "SCP-NAME"

    mapfile -t processes < <(ps aux --sort=-pcpu | head -10 | awk 'NR==1 {next} {printf "%s\t%s\t%s\t%s\n", $2, $3, $1, $11}')

    if [[ ${#processes[@]} -gt 0 ]]; then
        for process in "${processes[@]}"; do
            IFS=$'\t' read -r pid cpu user command <<< "$process"

            if [[ "$user" != "root" && $user =~ ^d_ ]]; then
                extracted_env=$(echo "$user" | cut -d '_' -f2)
                getScpEntryIdByPId "$extracted_env" "server -pid $pid"
                scp_id="${scp_details[scp_id]}"
                scp_name="${scp_details[scp_name]}"
            else
                if [[ "$command" == *"sentinel"* ]]; then
                    scp_id="sentinel"
                    scp_name="sentinel"
                else
                    scp_id="OSProcess"
                    scp_name="OSProcess"
                fi
            fi

            printf -v line "%-8s %-12s %-8s %-12s %s\n" "$pid" "$cpu" "$user" "$scp_id" "$scp_name"
            top_cpu_processes+="$line"
        done
    else
        top_cpu_processes+="No processes found.\n"
    fi

    printf "%s" "$top_cpu_processes"
}
```

- **Line 830-861**: Defines the `high_cpu_consumers` function, similar to `high_memory_consumers` but for CPU usage:
  - Same logic as above, sorting by CPU usage (`--sort=-pcpu`).

---

### **CPU Usage Check**

```bash
# Check for current cpu usage over 1 second
check_cpu_usage() {
    local target_host="$1"

    # Check if mpstat is installed
    if ! command -v mpstat &> /dev/null; then
        echo_log "||${Red} Failed :${NC} mpstat command not found. Please install sysstat package." "ERROR"
        updateJson "checks" "checkCpu" "name" "$current_node" "appNode"
        updateJson "checks" "checkCpu" "status" "Failed" "appNode"
        updateJson "checks" "checkCpu" "comment" "mpstat command not found. Please install sysstat package" "appNode"
        return 1
    fi

    # Determine if we are checking the current host or a remote one
    if [ -z "$target_host" ]; then
        echo_log -silent "Retreiving CPU usage of the current node." "INFO"
        cpu_idle=$(LANG=C mpstat 1 1 | awk '/Average/ {print $NF}')
    else
        echo_log -silent "Retreiving CPU usage of the target node

You're right, the script appears to be cut off in the middle of the `check_cpu_usage` function. Let me provide a complete explanation of the remaining parts of the script, assuming a typical structure based on the provided code and its patterns. Since the script is incomplete, I'll infer the likely continuation of the `check_cpu_usage` function and any remaining functions or script logic, based on the context and conventions used earlier. I'll also summarize the script's overall purpose and structure for clarity.

---

### **Remaining Code Analysis**

The script is a Bash script designed to perform health checks on a Cerner Millennium environment, validating system components, services, and resources, and generating a JSON report. The incomplete section is the `check_cpu_usage` function, which checks CPU usage on the current or a target node. Below, I'll complete the explanation of this function and infer the likely structure of any remaining functions (e.g., `checkMemory`, `checkCitrix`, `checkTrnrfsh`) based on the JSON template and the script's pattern.

#### **Completion of `check_cpu_usage` Function**

The `check_cpu_usage` function is checking CPU usage using `mpstat`. Here's how it likely continues:

```bash
# Check for current cpu usage over 1 second
check_cpu_usage() {
    local target_host="$1"

    # Check if mpstat is installed
    if ! command -v mpstat &> /dev/null; then
        echo_log "||${Red} Failed :${NC} mpstat command not found. Please install sysstat package." "ERROR"
        updateJson "checks" "checkCpu" "name" "$current_node" "appNode"
        updateJson "checks" "checkCpu" "status" "Failed" "appNode"
        updateJson "checks" "checkCpu" "comment" "mpstat command not found. Please install sysstat package" "appNode"
        return 1
    fi

    # Determine if we are checking the current host or a remote one
    if [ -z "$target_host" ]; then
        echo_log -silent "Retrieving CPU usage of the current node." "INFO"
        cpu_idle=$(LANG=C mpstat 1 1 | awk '/Average/ {print $NF}')
    else
        echo_log -silent "Retrieving CPU usage of the target node $target_host." "INFO"
        cpu_idle=$(ssh $target_host "LANG=C mpstat 1 1" 2>/dev/null | awk '/Average/ {print $NF}')
        if [ $? -ne 0 ]; then
            echo_log "||${Red} Failed :${NC} Unable to retrieve CPU usage from $target_host." "ERROR"
            updateJson "checks" "checkCpu" "name" "$target_host" "dbNode"
            updateJson "checks" "checkCpu" "status" "Failed" "dbNode"
            updateJson "checks" "checkCpu" "comment" "Unable to retrieve CPU usage from $target_host" "dbNode"
            return 1
        fi
    fi

    # Calculate CPU usage (100 - idle percentage)
    cpu_usage=$(echo "100 - $cpu_idle" | bc)

    # Define thresholds
    local high_threshold=90
    local warn_threshold=70

    # Check CPU usage against thresholds
    if (( $(echo "$cpu_usage >= $high_threshold" | bc -l) )); then
        echo_log "||${Red} Failed :${NC} CPU usage on $target_host is high: $cpu_usage%." "ERROR"
        updateJson "checks" "checkCpu" "status" "Failed" "${target_host:-appNode}"
        updateJson "checks" "checkCpu" "comment" "CPU usage is high: $cpu_usage%" "${target_host:-appNode}"
        if [ -z "$target_host" ]; then
            top_cpu=$(high_cpu_consumers)
            updateJson "checks" "checkCpu" "processes" "$top_cpu" "appNode"
            updateJson "checks" "checkCpu" "recommendations" "Review high CPU consumers and consider scaling resources." "appNode"
        fi
        return 1
    elif (( $(echo "$cpu_usage >= $warn_threshold" | bc -l) )); then
        echo_log "||${Yellow} Warning :${NC} CPU usage on $target_host is elevated: $cpu_usage%." "WARN"
        updateJson "checks" "checkCpu" "status" "Partial" "${target_host:-appNode}"
        updateJson "checks" "checkCpu" "comment" "CPU usage is elevated: $cpu_usage%" "${target_host:-appNode}"
        if [ -z "$target_host" ]; then
            top_cpu=$(high_cpu_consumers)
            updateJson "checks" "checkCpu" "processes" "$top_cpu" "appNode"
            updateJson "checks" "checkCpu" "recommendations" "Monitor CPU usage and consider optimization." "appNode"
        fi
        return 0
    else
        echo_log "||${Green} Success:${NC} CPU usage on $target_host is normal: $cpu_usage%." "INFO"
        updateJson "checks" "checkCpu" "status" "Passed" "${target_host:-appNode}"
        updateJson "checks" "checkCpu" "comment" "CPU usage is normal: $cpu_usage%" "${target_host:-appNode}"
        if [ -z "$target_host" ]; then
            top_cpu=$(high_cpu_consumers)
            updateJson "checks" "checkCpu" "processes" "$top_cpu" "appNode"
        fi
        return 0
    fi
}
```

**Explanation**:
- **Line 863-867**: Checks if `mpstat` is installed; if not, logs an error, updates JSON for `appNode`, and exits.
- **Line 870-878**: If no `target_host` is provided, runs `mpstat` locally to get CPU idle percentage. If a target host is provided, uses `ssh` to run `mpstat` remotely and handles errors.
- **Line 881**: Calculates CPU usage as `100 - idle%`.
- **Line 884-885**: Defines thresholds for high (90%) and warning (70%) CPU usage.
- **Line 888-898**: If CPU usage exceeds the high threshold, logs a failure, updates JSON, and includes top CPU consumers for the application node.
- **Line 899-909**: If CPU usage is in the warning range, logs a warning, updates JSON, and includes top CPU consumers.
- **Line 910-918**: If CPU usage is normal, logs success, updates JSON, and includes top CPU consumers for the application node.

#### **Inferred `checkMemory` Function**

Based on the JSON template and the pattern of other checks, the `checkMemory` function likely checks memory usage on the application and database nodes, similar to `check_cpu_usage`. Here's a plausible implementation:

```bash
checkMemory() {
    local target_host="$1"

    echo_log -silent "Checking memory usage on ${target_host:-$current_node}." "INFO"

    # Check if free command is available
    if ! command -v free &> /dev/null; then
        echo_log "||${Red} Failed :${NC} free command not found." "ERROR"
        updateJson "checks" "checkMemory" "name" "$current_node" "appNode"
        updateJson "checks" "checkMemory" "status" "Failed" "appNode"
        updateJson "checks" "checkMemory" "comment" "free command not found" "appNode"
        return 1
    fi

    # Get memory usage
    if [ -z "$target_host" ]; then
        mem_info=$(free -m | awk '/Mem:/ {print $3/$2*100}')
    else
        mem_info=$(ssh $target_host "free -m" 2>/dev/null | awk '/Mem:/ {print $3/$2*100}')
        if [ $? -ne 0 ]; then
            echo_log "||${Red} Failed :${NC} Unable to retrieve memory usage from $target_host." "ERROR"
            updateJson "checks" "checkMemory" "name" "$target_host" "dbNode"
            updateJson "checks" "checkMemory" "status" "Failed" "dbNode"
            updateJson "checks" "checkMemory" "comment" "Unable to retrieve memory usage from $target_host" "dbNode"
            return 1
        fi
    fi

    mem_usage=$(echo "$mem_info" | bc)

    # Define thresholds
    local high_threshold=90
    local warn_threshold=70

    # Check memory usage against thresholds
    if (( $(echo "$mem_usage >= $high_threshold" | bc -l) )); then
        echo_log "||${Red} Failed :${NC} Memory usage on $target_host is high: $mem_usage%." "ERROR"
        updateJson "checks" "checkMemory" "status" "Failed" "${target_host:-appNode}"
        updateJson "checks" "checkMemory" "comment" "Memory usage is high: $mem_usage%" "${target_host:-appNode}"
        if [ -z "$target_host" ]; then
            top_mem=$(high_memory_consumers)
            updateJson "checks" "checkMemory" "processes" "$top_mem" "appNode"
            updateJson "checks" "checkMemory" "recommendations" "Review high memory consumers and consider scaling resources." "appNode"
        fi
        return 1
    elif (( $(echo "$mem_usage >= $warn_threshold" | bc -l) )); then
        echo_log "||${Yellow} Warning :${NC} Memory usage on $target_host is elevated: $mem_usage%." "WARN"
        updateJson "checks" "checkMemory" "status" "Partial" "${target_host:-appNode}"
        updateJson "checks" "checkMemory" "comment" "Memory usage is elevated: $mem_usage%" "${target_host:-appNode}"
        if [ -z "$target_host" ]; then
            top_mem=$(high_memory_consumers)
            updateJson "checks" "checkMemory" "processes" "$top_mem" "appNode"
            updateJson "checks" "checkMemory" "recommendations" "Monitor memory usage and consider optimization." "appNode"
        fi
        return 0
    else
        echo_log "||${Green} Success:${NC} Memory usage on $target_host is normal: $mem_usage%." "INFO"
        updateJson "checks" "checkMemory" "status" "Passed" "${target_host:-appNode}"
        updateJson "checks" "checkMemory" "comment" "Memory usage is normal: $mem_usage%" "${target_host:-appNode}"
        if [ -z "$target_host" ]; then
            top_mem=$(high_memory_consumers)
            updateJson "checks" "checkMemory" "processes" "$top_mem" "appNode"
        fi
        return 0
    fi
}
```

**Explanation**:
- Similar to `check_cpu_usage`, this function checks memory usage using the `free` command, calculates the percentage used, and compares it against thresholds (90% for high, 70% for warning).
- Logs results, updates JSON, and includes top memory consumers for the application node.

#### **Inferred `checkCitrix` Function**

The JSON template includes a `checkCitrix` section, suggesting a check for Citrix-related services. Here's a likely implementation:

```bash
checkCitrix() {
    echo_log -silent "Checking Citrix connectivity for $mill_env." "INFO"

    # Check if Citrix services are running
    if systemctl is-active --quiet citrix 2>/dev/null; then
        echo_log "||${Green} Success:${NC} Citrix services are running." "INFO"
        updateJson "checks" "checkCitrix" "status" "Passed"
        updateJson "checks" "checkCitrix" "comment" "Citrix services are running"
        return 0
    else
        echo_log "||${Red} Failed :${NC} Citrix services are not running." "ERROR"
        updateJson "checks" "checkCitrix" "status" "Failed"
        updateJson "checks" "checkCitrix" "comment" "Citrix services are not running"
        return 1
    fi
}
```

**Explanation**:
- Checks if Citrix services are active using `systemctl`.
- Logs success or failure and updates JSON accordingly.

#### **Inferred `checkTrnrfsh` Function**

The `checkTrnrfsh` function, referenced earlier, checks the status of `trnrfsh` (train domain refresh) jobs. Here's a plausible implementation:

```bash
checkTrnrfsh() {
    echo_log -silent "Checking trnrfsh job status for $mill_env." "INFO"
    checkTrnrfsh_flag="1"

    local cron_schedule=$(crontab -l | grep -i "$mill_env" | grep -E -wi 'trnrfsh|crontab_master.ksh' | grep -v '^#' | awk '{print $1,$2,$3,$4,$5}')
    local timezone=$(timedatectl | grep "Time zone" | awk '{print $3}')
    local log_file="/cerner/mgr/logs/trnrfsh_${mill_env}.log"
    local log_state=""
    local snapshot_date=""
    local email_recipients=""
    local trnrfsh_log_tail=""

    if [ -n "$cron_schedule" ]; then
        if [ -f "$log_file" ]; then
            log_state="Exists"
            snapshot_date=$(grep -i "snapshot" "$log_file" | tail -1 | awk '{print $1,$2}')
            trnrfsh_log_tail=$(tail -n 10 "$log_file")
            email_recipients=$(grep -i "email" "$log_file" | tail -1 | awk '{print $NF}')
        else
            log_state="Not Found"
        fi
        echo_log "||${Green} Success:${NC} Trnrfsh job is scheduled for $mill_env." "INFO"
        updateJson "checks" "checkTrnrfsh" "status" "Passed"
        updateJson "checks" "checkTrnrfsh" "comment" "Trnrfsh job is scheduled"
        updateJson "checks" "checkTrnrfsh" "cronschedule" "$cron_schedule"
        updateJson "checks" "checkTrnrfsh" "timezone" "$timezone"
        updateJson "checks" "checkTrnrfsh" "snapshot_date" "$snapshot_date"
        updateJson "checks" "checkTrnrfsh" "emailrecipients" "$email_recipients"
        updateJson "checks" "checkTrnrfsh" "logfile" "$log_file"
        updateJson "checks" "checkTrnrfsh" "logstate" "$log_state"
        updateJson "checks" "checkTrnrfsh" "trnrfshlogtail" "$trnrfsh_log_tail"
    else
        echo_log "||${Yellow} Warning :${NC} No trnrfsh job is scheduled for $mill_env." "WARN"
        updateJson "checks" "checkTrnrfsh" "status" "Partial"
        updateJson "checks" "checkTrnrfsh" "comment" "No trnrfsh job is scheduled"
    fi

    return 0
}
```

**Explanation**:
- Checks the crontab for `trnrfsh` jobs, retrieves schedule, timezone, log file details, and the last 10 lines of the log.
- Updates JSON with detailed job information or a warning if no job is scheduled.

#### **Main Execution Block**

The script likely concludes with a main execution block that orchestrates the checks. Here's a typical implementation:

```bash
# Main execution
cleanupFiles
check_jq_installed

# Update top-level JSON fields
updateJson "" "" "hostname" "$current_node"
updateJson "" "" "environment" "$mill_env"
updateJson "" "" "date" "$(date '+%Y-%m-%d %H:%M:%S')"
updateJson "" "" "logfile" "$LOGFILE"

# Perform initial checks
maintenanceState
cronjobState
envValidation "$mill_env"

# Source environment file
if envFileCheck "$mill_env"; then
    source "/cerner/mgr/${mill_env}_environment.ksh"
    updateJson "prerequisites" "sourceEnv" "status" "Passed"
    updateJson "prerequisites" "sourceEnv" "comment" "Environment file sourced successfully"
else
    echo_log "||${Red} Failed :${NC} Environment file /cerner/mgr/${mill_env}_environment.ksh does not exist." "ERROR"
    updateJson "prerequisites" "sourceEnv" "status" "Failed"
    updateJson "prerequisites" "sourceEnv" "comment" "Environment file does not exist"
    exit 1
fi

# Set credentials and collect system info
setMillUserPass
generalInfo

# Run health checks
checkRegistry
checkMQ "$mill_env"
checkTestsec "$mill_env"
checkDeadScpServers "$mill_env"
checkCCL "$mill_env"
checkSystest "$mill_env"
checkMpage
check_cpu_usage ""
check_cpu_usage "$db_host"
checkMemory ""
checkMemory "$db_host"
checkCitrix

# Run trnrfsh check if not already run
if [ "$checkTrnrfsh_flag" == "0" ]; then
    checkTrnrfsh
fi

# Generate final JSON file
remoteFileName="/tmp/train_domain_checks_${current_node}_${mill_env}.json"
echo "$updatedJson" > "$remoteFileName"
updateJson "" "" "remoteFileName" "$remoteFileName"

echo_log "\n||${CYAN} Info   :${NC} Generated JSON file: $remoteFileName"
echo_log "||${CYAN} Info   :${NC} Generated log file: $LOGFILE"
echo_log "${Blue}\nScript Execution Completed.${NC}\n"

exit 0
```

**Explanation**:
- Cleans up old files and checks for `jq`.
- Updates top-level JSON fields (hostname, environment, date, logfile).
- Performs blocking checks (`maintenanceState`, `cronjobState`, `envValidation`).
- Sources the environment file and retrieves credentials.
- Runs all health checks in sequence, including CPU and memory for both nodes.
- Generates the final JSON report and logs completion.

---

### **Overall Script Summary**

**Purpose**: The script performs comprehensive health checks on a Cerner Millennium environment, validating system components (registry, MQ, testsec, SCP, CCL, mPage, systest, CPU, memory, Citrix) and `trnrfsh` jobs. It generates a JSON report summarizing the results and logs details to a file.

**Key Features**:
- **Input Validation**: Requires `-env` flag and an environment name.
- **Root Check**: Must run as root.
- **Logging**: Uses a custom `echo_log` function to log to console and file.
- **JSON Reporting**: Maintains a structured JSON report for all checks.
- **Maintenance and Cron Checks**: Aborts if maintenance or `trnrfsh` jobs are active.
- **System Checks**: Validates environment, credentials, and various services.
- **Resource Monitoring**: Checks CPU and memory usage with thresholds.
- **Cleanup**: Manages temporary files and keeps only the latest two logs.

**Execution Flow**:
1. Validates inputs and environment.
2. Checks for blockers (maintenance, `trnrfsh` jobs).
3. Sources environment files and retrieves credentials.
4. Collects system information (uptime, OS, Java, MQ, etc.).
5. Performs health checks on services and resources.
6. Generates a JSON report and logs results.

**Output**:
- A log file (`/tmp/train_domain_checks_YYYY-MM-DD_HH-MM-SS.out`).
- A JSON file (`/tmp/train_domain_checks_${current_node}_${mill_env}.json`) with detailed check results.

---

### **Addressing Your Query**

The script was indeed incomplete, ending mid-function. I've provided a reasoned completion of the `check_cpu_usage` function and inferred implementations for `checkMemory`, `checkCitrix`, `checkTrnrfsh`, and the main execution block, based on the script's structure and JSON template. If you have the full script or specific sections you'd like me to analyze further, please provide them, and I can refine the explanation. Alternatively, if you have specific questions about the script's functionality or need help with debugging or enhancements, let me know!
