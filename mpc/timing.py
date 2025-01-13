import time
import os

class AnalysisTimer:
    def __init__(self, party_index):
        log_file = f"analysis_times_{party_index}.log"
        self.log_file = log_file
        self.start_times = {}

    def start(self, analysis_id):
        """
        Record the start time for a specific analysis.
        If the analysis ID already exists, it will overwrite the previous entry.
        
        Arguments:
            analysis_id (str): The unique ID of the analysis.
        """
        if analysis_id in self.start_times:
            print(f"Overwriting existing start time for analysis ID: {analysis_id}")
        self.start_times[analysis_id] = time.time()

    def end(self, analysis_id):
        """
        Record the end time for a specific analysis and log the duration.
        If the analysis ID is not found, log an error message.
        
        Arguments:
            analysis_id (str): The unique ID of the analysis.
        """
        if analysis_id not in self.start_times:
            print(f"No existing start time for analysis ID: {analysis_id}. Cannot calculate duration.")
            return
        
        end_time = time.time()
        duration = end_time - self.start_times.pop(analysis_id)
        
        # Save the timing information
        self.save(analysis_id, duration)

    def save(self, analysis_id, duration):
        """
        Save the analysis timing to a log file.
        
        Arguments:
            analysis_id (str): The unique ID of the analysis.
            duration (float): The duration of the analysis in seconds.
        """
        with open(self.log_file, "a") as log:
            log.write(f"Analysis ID: {analysis_id}, Duration: {duration:.2f} seconds\n")
