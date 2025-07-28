self.onmessage = async function (event) {
    if (!detector) {
      console.error("AprilTag detector is not initialized yet!");
      return;
    }
  
    const { imageData, width, height } = event.data;
    console.log(`Worker received image: ${width}x${height}`);
  
    // Ensure the `detect` function exists
    if (typeof detector.detect !== "function") {
      console.error("AprilTag detector.detect() is not available!");
      return;
    }
  
    try {
      let detections = await detector.detect(imageData, width, height);
      console.log("Detections:", detections);
      
      // Send detections back to the main thread
      self.postMessage({
        type: "detection",
        detections: detections
      });
  
    } catch (error) {
      console.error("Error during AprilTag detection:", error);
    }
  };
  