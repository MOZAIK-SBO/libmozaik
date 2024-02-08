from analysis_app import AnalysisApp
import sys

if __name__ == '__main__':
    app = AnalysisApp(sys.argv[1])
    app.start_background_thread()
