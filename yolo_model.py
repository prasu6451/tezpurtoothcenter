import os
import shutil

def run_yolo_analysis(image_path):
    """
    Mock YOLO analysis: just copies the image and returns fake detection data.
    Replace this with actual YOLO inference code.
    """
    # Simulate saving an annotated version
    result_path = image_path.replace("uploads", "results")
    os.makedirs(os.path.dirname(result_path), exist_ok=True)
    shutil.copy(image_path, result_path)

    # Dummy detection results
    detections = [
        {"label": "Tooth Cavity", "confidence": 0.87},
        {"label": "Impacted Tooth", "confidence": 0.76}
    ]

    return result_path, detections
