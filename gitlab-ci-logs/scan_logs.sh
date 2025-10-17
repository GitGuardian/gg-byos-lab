#!/bin/bash
set -e

# Validate required environment variables
for var in SOURCE_UUID GITLAB_TOKEN GITGUARDIAN_API_KEY; do
    if [ -z "${!var}" ]; then
        echo "❌ Error: $var environment variable is not set"
        exit 1
    fi
done

# GitLab API configuration from CI environment
GITLAB_API_URL="$CI_API_V4_URL"
PROJECT_ID="$CI_PROJECT_ID" 
PIPELINE_ID="$CI_PIPELINE_ID"
AUTH_HEADER="Authorization: Bearer $GITLAB_TOKEN"

echo "🔍 Scanning logs for pipeline $PIPELINE_ID in project $PROJECT_ID"

scan_failures=0

# Function to download and scan individual job logs
scan_job_log() {
    local job_id="$1"
    local job_name="$2" 
    local log_file="/tmp/job_${job_id}_log.txt"
    
    echo "📋 Processing job: $job_name (ID: $job_id)"
    
    # Download job log via GitLab API
    if curl -s -H "$AUTH_HEADER" \
        "$GITLAB_API_URL/projects/$PROJECT_ID/jobs/$job_id/trace" \
        -o "$log_file"; then
        
        # Only scan non-empty logs
        if [ -s "$log_file" ]; then
            echo "🔎 Scanning log file for job $job_name..."
            
            # Run ggshield with custom source UUID
            if ggshield secret scan path "$log_file" --source-uuid "$SOURCE_UUID"; then
                echo "✅ Scan completed successfully for job: $job_name"
            else
                echo "❌ Scan failed for job: $job_name"
                ((scan_failures++))
            fi
        else
            echo "⚠️  Log file for job $job_name is empty, skipping"
        fi
        
        # Cleanup temporary file
        rm -f "$log_file"
    else
        echo "❌ Failed to download log for job: $job_name"
        ((scan_failures++))
    fi
}

# Fetch all jobs in current pipeline
echo "📡 Fetching jobs for pipeline $PIPELINE_ID..."

jobs_data=$(curl -s -H "$AUTH_HEADER" \
    "$GITLAB_API_URL/projects/$PROJECT_ID/pipelines/$PIPELINE_ID/jobs")

# Validate API response
if ! echo "$jobs_data" | jq -e . >/dev/null 2>&1; then
    echo "❌ Failed to fetch jobs data or invalid JSON response"
    echo "Response: $jobs_data"
    exit 1
fi

job_count=$(echo "$jobs_data" | jq '. | length')
echo "📊 Found $job_count jobs in pipeline"

# Process each job
for i in $(seq 0 $((job_count - 1))); do
    job_id=$(echo "$jobs_data" | jq -r ".[$i].id")
    job_name=$(echo "$jobs_data" | jq -r ".[$i].name") 
    job_status=$(echo "$jobs_data" | jq -r ".[$i].status")
    
    # Skip jobs without completed logs
    case "$job_status" in
        created|pending|running)
            echo "⏳ Skipping job $job_name (status: $job_status) - no logs available"
            continue
            ;;
    esac
    
    scan_job_log "$job_id" "$job_name"
done

# Report final results
if [ $scan_failures -gt 0 ]; then
    echo "❌ $scan_failures job(s) failed during log scanning"
    exit 1
fi

echo "🎉 Log scanning completed successfully for all jobs in pipeline $PIPELINE_ID"