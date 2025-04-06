from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
# Define tasks with durations and start dates for daily allocation
tasks_daily = [
    ("Directory Traversal Implementation", 2, datetime(2024, 9, 20)),
    ("Virus Database Handling", 1, datetime(2024, 9, 22)),
    ("Feature Extraction", 2, datetime(2024, 9, 23)),
    ("Model Training", 3, datetime(2024, 9, 25)),
    ("October Free Period", 30, datetime(2024, 10, 1)),  # October break
    ("GUI Development", 5, datetime(2024, 11, 1)),
    ("Integration & Testing", 15, datetime(2024, 11, 15)),
    ("Project Completion", 1, datetime(2024, 12, 5))
]

# Generate daily data for the Gantt chart
daily_tasks = []
for task, duration, start_date in tasks_daily:
    if task == "October Free Period":
        continue  # Skip October break in the daily breakdown
    for day in range(duration):
        daily_tasks.append((task, start_date + timedelta(days=day)))

# Extract unique days and tasks for plotting
dates = sorted({date for _, date in daily_tasks})
task_map = {task: i + 1 for i, task in enumerate(set(task for task, _ in daily_tasks))}

# Plot the Gantt chart on a daily basis
fig, ax = plt.subplots(figsize=(14, 8))
for task, date in daily_tasks:
    ax.barh(task_map[task], 1, left=mdates.date2num(date), color="lightblue", edgecolor="black")

# Highlight weekends in the daily timeline
start_date = min(dates)
end_date = max(dates)
weekends = [start_date + timedelta(days=i) for i in range((end_date - start_date).days + 1) if (start_date + timedelta(days=i)).weekday() >= 5]
for weekend in weekends:
    ax.axvspan(mdates.date2num(weekend), mdates.date2num(weekend + timedelta(days=1)), color='pink', alpha=0.2)

# Format chart
ax.set_yticks(list(task_map.values()))
ax.set_yticklabels(list(task_map.keys()))
ax.xaxis.set_major_locator(mdates.DayLocator(interval=3))
ax.xaxis.set_major_formatter(mdates.DateFormatter('%b %d'))
ax.xaxis_date()
plt.xticks(rotation=45)
plt.xlabel("Timeline")
plt.ylabel("Tasks")
plt.title("Daily Breakdown Gantt Chart with Focus on Weekends")

# Show the chart
plt.tight_layout()
plt.show()
