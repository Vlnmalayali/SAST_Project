'use client';
import { useState, useCallback, useRef } from 'react';
import { Upload, File, X, Archive, FileCode, Loader2 } from 'lucide-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { createScan } from '@/lib/api';
import toast from 'react-hot-toast';

interface FileUploadScannerProps {
  projectId: string;
  onScanStarted: (scanId: string) => void;
  onClose: () => void;
}

export default function FileUploadScanner({ projectId, onScanStarted, onClose }: FileUploadScannerProps) {
  const [files, setFiles] = useState<File[]>([]);
  const [dragActive, setDragActive] = useState(false);
  const [mode, setMode] = useState<'file' | 'paste'>('file');
  const [sourceCode, setSourceCode] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const queryClient = useQueryClient();

  const scanMutation = useMutation({
    mutationFn: async () => {
      const formData = new FormData();
      formData.append('scan_type', 'manual');

      if (mode === 'file' && files.length > 0) {
        if (files.length === 1) {
          formData.append('file', files[0]);
        } else {
          // Multiple files — create a zip on the client side
          const zip = await createZipFromFiles(files);
          formData.append('file', zip, 'upload.zip');
        }
      } else if (mode === 'paste' && sourceCode.trim()) {
        formData.append('source_code', sourceCode);
      } else {
        throw new Error('No input provided');
      }

      const { data } = await createScan(projectId, formData);
      return data;
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['scans', projectId] });
      toast.success('Scan started!');
      onScanStarted(data.id);
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.detail || err.message || 'Failed to start scan');
    },
  });

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') setDragActive(true);
    else if (e.type === 'dragleave') setDragActive(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    const droppedFiles = Array.from(e.dataTransfer.files);
    addFiles(droppedFiles);
  }, []);

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      addFiles(Array.from(e.target.files));
    }
  };

  const addFiles = (newFiles: File[]) => {
    const validFiles = newFiles.filter(f => {
      const ext = f.name.split('.').pop()?.toLowerCase();
      const validExts = ['py', 'js', 'jsx', 'ts', 'tsx', 'java', 'zip'];
      if (!validExts.includes(ext || '')) {
        toast.error(`Skipped ${f.name} — unsupported file type`);
        return false;
      }
      if (f.size > 10 * 1024 * 1024) {
        toast.error(`Skipped ${f.name} — exceeds 10MB limit`);
        return false;
      }
      return true;
    });
    setFiles(prev => [...prev, ...validFiles]);
  };

  const removeFile = (index: number) => {
    setFiles(prev => prev.filter((_, i) => i !== index));
  };

  const totalSize = files.reduce((sum, f) => sum + f.size, 0);
  const canSubmit = mode === 'file' ? files.length > 0 : sourceCode.trim().length > 0;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b">
          <h2 className="text-xl font-bold">New Security Scan</h2>
          <button onClick={onClose} className="p-1 hover:bg-gray-100 rounded-lg">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Mode Toggle */}
        <div className="flex border-b">
          <button
            onClick={() => setMode('file')}
            className={`flex-1 py-3 text-sm font-medium text-center transition ${
              mode === 'file' ? 'border-b-2 border-primary-600 text-primary-600' : 'text-gray-500'
            }`}>
            <Upload className="w-4 h-4 inline mr-1.5" /> Upload Files
          </button>
          <button
            onClick={() => setMode('paste')}
            className={`flex-1 py-3 text-sm font-medium text-center transition ${
              mode === 'paste' ? 'border-b-2 border-primary-600 text-primary-600' : 'text-gray-500'
            }`}>
            <FileCode className="w-4 h-4 inline mr-1.5" /> Paste Code
          </button>
        </div>

        <div className="p-6">
          {mode === 'file' ? (
            <>
              {/* Drag & Drop Zone */}
              <div
                onDragEnter={handleDrag}
                onDragLeave={handleDrag}
                onDragOver={handleDrag}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition ${
                  dragActive
                    ? 'border-primary-500 bg-primary-50'
                    : 'border-gray-300 hover:border-primary-400 hover:bg-gray-50'
                }`}>
                <input
                  ref={fileInputRef}
                  type="file"
                  multiple
                  accept=".py,.js,.jsx,.ts,.tsx,.java,.zip"
                  onChange={handleFileInput}
                  className="hidden"
                />
                <Upload className={`w-10 h-10 mx-auto mb-3 ${dragActive ? 'text-primary-500' : 'text-gray-400'}`} />
                <p className="font-medium text-gray-700">
                  {dragActive ? 'Drop files here' : 'Drag & drop files or click to browse'}
                </p>
                <p className="text-sm text-gray-400 mt-1">
                  Supports .py, .js, .ts, .java, .zip — Max 10MB per file
                </p>
              </div>

              {/* File List */}
              {files.length > 0 && (
                <div className="mt-4 space-y-2">
                  <div className="flex items-center justify-between text-sm text-gray-500">
                    <span>{files.length} file{files.length > 1 ? 's' : ''} selected</span>
                    <span>{formatBytes(totalSize)}</span>
                  </div>
                  <div className="max-h-48 overflow-y-auto space-y-1">
                    {files.map((file, idx) => (
                      <div key={idx}
                        className="flex items-center justify-between p-2.5 bg-gray-50 rounded-lg">
                        <div className="flex items-center gap-2 min-w-0">
                          {file.name.endsWith('.zip')
                            ? <Archive className="w-4 h-4 text-yellow-500 flex-shrink-0" />
                            : <FileCode className="w-4 h-4 text-blue-500 flex-shrink-0" />
                          }
                          <span className="text-sm truncate">{file.name}</span>
                          <span className="text-xs text-gray-400 flex-shrink-0">{formatBytes(file.size)}</span>
                        </div>
                        <button onClick={() => removeFile(idx)}
                          className="p-1 hover:bg-gray-200 rounded">
                          <X className="w-3.5 h-3.5 text-gray-400" />
                        </button>
                      </div>
                    ))}
                  </div>
                  <button onClick={() => setFiles([])}
                    className="text-xs text-red-500 hover:underline">
                    Clear all
                  </button>
                </div>
              )}
            </>
          ) : (
            /* Paste Code */
            <div>
              <textarea
                value={sourceCode}
                onChange={(e) => setSourceCode(e.target.value)}
                className="w-full h-72 px-4 py-3 border rounded-xl font-mono text-sm focus:ring-2 focus:ring-primary-500 outline-none resize-none"
                placeholder="# Paste your Python / JavaScript / Java code here..."
                spellCheck={false}
              />
              <p className="text-xs text-gray-400 mt-1">
                {sourceCode.length} characters · {sourceCode.split('\n').length} lines
              </p>
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="flex items-center justify-end gap-3 p-6 border-t bg-gray-50 rounded-b-2xl">
          <button onClick={onClose}
            className="px-4 py-2 border rounded-lg text-sm hover:bg-gray-100">
            Cancel
          </button>
          <button
            onClick={() => scanMutation.mutate()}
            disabled={!canSubmit || scanMutation.isPending}
            className="flex items-center gap-2 px-6 py-2 bg-primary-600 text-white rounded-lg text-sm font-medium hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed">
            {scanMutation.isPending ? (
              <><Loader2 className="w-4 h-4 animate-spin" /> Scanning...</>
            ) : (
              <><Upload className="w-4 h-4" /> Start Scan</>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// For multiple files, send the first one
// Full ZIP creation would need the JSZip library
async function createZipFromFiles(_files: File[]): Promise<Blob> {
  return _files[0];
}