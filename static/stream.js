        let isStreaming = false;
        let descriptionsInterval;

        // DOM elements
        const startBtn = document.getElementById('playBtn');
        const stopBtn = document.getElementById('stopBtnOverlay');
        const videoStream = document.getElementById('videoStream');
        const noVideo = document.getElementById('noVideo');
        const status = document.getElementById('status');
        const transcriptBox = document.getElementById('transcriptBox');

        // Event listeners
        startBtn.addEventListener('click', startStream);
        stopBtnOverlay.addEventListener('click', stopStream);

        function showStatus(message, type = 'success') {
            status.textContent = message;
            status.className = `status ${type}`;
            status.style.display = 'block';
            
            setTimeout(() => {
                status.style.display = 'none';
            }, 3000);
        }

        function startStream() {

            const videoUrlInput = document.getElementById('videoUrl');
            const videoUrl = videoUrlInput ? videoUrlInput.value.trim() : "0";
            
            // You can validate here if needed
            if (!videoUrl) {
                showStatus("Please enter a valid video URL before starting.", "error");
                return;
            }

            // Show spinner immediately
            noVideo.style.display = 'none';
            document.getElementById('loadingSpinner').style.display = 'flex';
            
            fetch('/start_stream', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }, 
                body: JSON.stringify({ url: videoUrl }) // 🔗 Send URL to server
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success' || data.status === 'info') {
                    startBtn.disabled = true;
                    stopBtn.disabled = false;
                    showStatus(data.message, 'success');
                    
                    // Set video source and wait for it to load
                    videoStream.src = '/video_feed?' + new Date().getTime();
                    
                    // Hide spinner when video loads
                    videoStream.onload = function() {
                        document.getElementById('loadingSpinner').style.display = 'none';
                        videoStream.style.display = 'block';
                        isStreaming = true;
                        startDescriptionPolling();
                    };
                    
                    // Fallback: hide spinner after 5 seconds regardless
                    setTimeout(() => {
                        if (document.getElementById('loadingSpinner').style.display !== 'none') {
                            document.getElementById('loadingSpinner').style.display = 'none';
                            videoStream.style.display = 'block';
                            isStreaming = true;
                            startDescriptionPolling();
                        }
                    }, 5000);
                    
                } else {
                    // Hide spinner and show error
                    document.getElementById('loadingSpinner').style.display = 'none';
                    noVideo.style.display = 'block';
                    showStatus(data.message, 'error');
                }
            })
            .catch(error => {
                console.error('Error starting stream:', error);
                document.getElementById('loadingSpinner').style.display = 'none';
                noVideo.style.display = 'block';
                showStatus('Failed to start stream', 'error');
            });
        }

        function stopStream() {
            fetch('/stop_stream', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            })
            .then(response => response.json())
            .then(data => {
                isStreaming = false;
                videoStream.style.display = 'none';
                videoStream.src = '';
                noVideo.style.display = 'block';
                
                startBtn.disabled = false;
                stopBtn.disabled = true;
                
                showStatus(data.message, 'success');
                
                // Stop polling for descriptions
                stopDescriptionPolling();

                // Download the mission report
                downloadMissionReport()
            })
            .catch(error => {
                console.error('Error stopping stream:', error);
                showStatus('Failed to stop stream', 'error');
            });
        }

        function startDescriptionPolling() {
            descriptionsInterval = setInterval(() => {
                if (isStreaming) {
                    fetchDescriptions();
                }
            }, 2000); // Poll every 2 seconds
        }

        function stopDescriptionPolling() {
            if (descriptionsInterval) {
                clearInterval(descriptionsInterval);
                descriptionsInterval = null;
            }
        }

        function downloadMissionReport() {
            try {
                const messages = extractTranscriptMessages();
                
                if (messages.length === 0) {
                    alert('No transcript messages to download.');
                    return;
                }
                
                const { doc, yPosition: startY, margin, maxWidth } = generatePDFReport(messages);
                let yPosition = startY;
                
                // Add messages to PDF
                doc.setFontSize(10);
                doc.setFont("ChakraPetch", 'normal');
                
                messages.forEach(message => {
                    // Check if we need a new page
                    if (yPosition > 270) {
                        doc.addPage();
                        yPosition = 20;
                    }
                    
                    // Message number
                    doc.setFont("ChakraPetch", 'normal');
                    doc.text(`[${message.id}]`, margin, yPosition);
                    
                    // Message content (with text wrapping)
                    doc.setFont("ChakraPetch", 'normal');
                    const lines = doc.splitTextToSize(message.content, maxWidth - 20);
                    doc.text(lines, margin + 15, yPosition);
                    
                    yPosition += (lines.length * 5) + 8;
                });
                
                // Generate filename
                const now = new Date();
                const timestamp = now.toISOString().slice(0, 19).replace(/:/g, '-');
                const missionTitle = document.getElementById('mission-title') ? 
                    document.getElementById('mission-title').textContent.replace('Mission Title: ', '').trim() : 'Mission';
                
                const cleanTitle = missionTitle.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 30);
                const filename = `${cleanTitle}_Report_${timestamp}.pdf`;
                
                // Save the PDF
                doc.save(filename);
                
                console.log(`✅ Mission report PDF downloaded: ${filename}`);
                showDownloadSuccess(filename);
                
            } catch (error) {
                console.error('Error downloading mission report:', error);
                alert('Error downloading PDF report. Please try again.');
            }
        }

        function fetchDescriptions() {
            fetch('/get_descriptions')
            .then(response => response.json())
            .then(data => {
                if (data.descriptions && data.descriptions.length > 0) {
                    addDescriptions(data.descriptions);
                }
            })
            .catch(error => {
                console.error('Error fetching descriptions:', error);
            });
        }

        function addDescriptions(descriptions) {
            descriptions.forEach(desc => {
                const descItem = document.createElement('div');
                descItem.className = 'description-item';
                
                descItem.innerHTML = `
                    <div class="description-time">${desc.timestamp}</div>
                    <div class="message">${desc.description}</div>
                `;
                
                // Add to top of container
                transcriptBox.insertBefore(descItem, transcriptBox.firstChild);
                
                // Remove old descriptions if too many (keep last 20)
                const items = transcriptBox.getElementsByClassName('description-item');
                if (items.length > 20) {
                    transcriptBox.removeChild(items[items.length - 1]);
                }
            });
            
            // Clear the placeholder text if it exists
            const placeholder = transcriptBox.querySelector('p[style*="text-align: center"]');
            if (placeholder) {
                placeholder.remove();
            }
            
            // Enable scrolling only when content exceeds height
            if (transcriptBox.scrollHeight > transcriptBox.clientHeight) {
            transcriptBox.style.overflowY = 'auto';
            }
                    }

        // Initialize button states
        startBtn.disabled = false;
        stopBtn.disabled = true;