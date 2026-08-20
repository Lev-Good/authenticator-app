using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace MasterAuthenticator
{
    public class QrCaptureWindow : Window
    {
        private System.Drawing.Bitmap _screenBmp;
        private Point _startPoint;
        private Canvas _canvas;
        private Rectangle _selectionRect;
        private Border _hintBorder;
        
        public System.Drawing.Bitmap? CroppedResult { get; private set; }

        [System.Runtime.InteropServices.DllImport("gdi32.dll")]
        public static extern bool DeleteObject(IntPtr hObject);

        public QrCaptureWindow(System.Drawing.Bitmap screenBmp)
        {
            _screenBmp = screenBmp;
            
            this.WindowStyle = WindowStyle.None;
            this.AllowsTransparency = true;
            this.Background = Brushes.Transparent;
            this.WindowState = WindowState.Maximized;
            this.Topmost = true;
            this.Cursor = Cursors.Cross;

            // Load screen capture image as brush for background visual
            var bitmapSource = ConvertToBitmapSource(screenBmp);
            var imageBrush = new ImageBrush(bitmapSource);
            
            // Create selection canvas
            _canvas = new Canvas { Background = imageBrush };
            this.Content = _canvas;

            // Semi-transparent dark mask overlay to dim the screen
            var dimMask = new Rectangle
            {
                Fill = new SolidColorBrush(Color.FromArgb(120, 15, 23, 42)), // dim color (slate 900)
                Width = SystemParameters.VirtualScreenWidth,
                Height = SystemParameters.VirtualScreenHeight
            };
            Canvas.SetLeft(dimMask, 0);
            Canvas.SetTop(dimMask, 0);
            _canvas.Children.Add(dimMask);

            // Selection rectangle (clear/un-dimmed, border color blue)
            _selectionRect = new Rectangle
            {
                Stroke = new SolidColorBrush(Color.FromRgb(14, 165, 233)), // sky blue
                StrokeThickness = 2.5,
                Fill = new ImageBrush(bitmapSource) { AlignmentX = AlignmentX.Left, AlignmentY = AlignmentY.Top, Stretch = Stretch.None },
                Visibility = Visibility.Collapsed
            };
            _canvas.Children.Add(_selectionRect);

            // Floating hint bar
            var hintText = new TextBlock
            {
                Text = "גרור מלבן עם העכבר מעל קוד ה-QR במסך כדי לסרוק (לחיצה ימנית או Esc לביטול)",
                Foreground = Brushes.White,
                FontSize = 14,
                FontWeight = FontWeights.Bold,
                HorizontalAlignment = HorizontalAlignment.Center
            };
            
            _hintBorder = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(200, 15, 23, 42)),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(15, 8, 15, 8),
                Child = hintText
            };
            
            _canvas.Children.Add(_hintBorder);
            
            this.Loaded += (s, e) =>
            {
                // Center the hint block
                Canvas.SetLeft(_hintBorder, (this.ActualWidth - _hintBorder.ActualWidth) / 2);
                Canvas.SetTop(_hintBorder, 40);
            };

            this.MouseDown += QrCaptureWindow_MouseDown;
            this.MouseMove += QrCaptureWindow_MouseMove;
            this.MouseUp += QrCaptureWindow_MouseUp;
            this.KeyDown += QrCaptureWindow_KeyDown;
        }

        private void QrCaptureWindow_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left)
            {
                _startPoint = e.GetPosition(_canvas);
                _selectionRect.Width = 0;
                _selectionRect.Height = 0;
                Canvas.SetLeft(_selectionRect, _startPoint.X);
                Canvas.SetTop(_selectionRect, _startPoint.Y);
                _selectionRect.Visibility = Visibility.Visible;
            }
            else if (e.ChangedButton == MouseButton.Right)
            {
                this.Close(); // Cancel on right click
            }
        }

        private void QrCaptureWindow_MouseMove(object sender, MouseEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed && _selectionRect.Visibility == Visibility.Visible)
            {
                var currentPoint = e.GetPosition(_canvas);
                
                double x = Math.Min(_startPoint.X, currentPoint.X);
                double y = Math.Min(_startPoint.Y, currentPoint.Y);
                double width = Math.Abs(_startPoint.X - currentPoint.X);
                double height = Math.Abs(_startPoint.Y - currentPoint.Y);

                Canvas.SetLeft(_selectionRect, x);
                Canvas.SetTop(_selectionRect, y);
                _selectionRect.Width = width;
                _selectionRect.Height = height;

                // Adjust viewport of fill image brush to match crop area
                if (_selectionRect.Fill is ImageBrush brush)
                {
                    brush.Viewbox = new Rect(x, y, width, height);
                    brush.ViewboxUnits = BrushMappingMode.Absolute;
                }
            }
        }

        private void QrCaptureWindow_MouseUp(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left)
            {
                double x = Canvas.GetLeft(_selectionRect);
                double y = Canvas.GetTop(_selectionRect);
                double width = _selectionRect.Width;
                double height = _selectionRect.Height;

                if (width > 8 && height > 8)
                {
                    // Convert WPF device-independent units to physical pixels
                    var source = PresentationSource.FromVisual(this);
                    double dpiX = 1.0;
                    double dpiY = 1.0;
                    if (source?.CompositionTarget != null)
                    {
                        dpiX = source.CompositionTarget.TransformToDevice.M11;
                        dpiY = source.CompositionTarget.TransformToDevice.M22;
                    }

                    int px = (int)(x * dpiX);
                    int py = (int)(y * dpiY);
                    int pWidth = (int)(width * dpiX);
                    int pHeight = (int)(height * dpiY);

                    // Constrain bounds to prevent exceptions
                    px = Math.Max(0, Math.Min(px, _screenBmp.Width - 1));
                    py = Math.Max(0, Math.Min(py, _screenBmp.Height - 1));
                    pWidth = Math.Min(pWidth, _screenBmp.Width - px);
                    pHeight = Math.Min(pHeight, _screenBmp.Height - py);

                    if (pWidth > 5 && pHeight > 5)
                    {
                        try
                        {
                            CroppedResult = _screenBmp.Clone(new System.Drawing.Rectangle(px, py, pWidth, pHeight), _screenBmp.PixelFormat);
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine("Crop error: " + ex.Message);
                        }
                    }
                }
                this.Close();
            }
        }

        private void QrCaptureWindow_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Escape)
            {
                this.Close(); // Cancel on Esc
            }
        }

        public static BitmapSource ConvertToBitmapSource(System.Drawing.Bitmap bitmap)
        {
            IntPtr hBitmap = bitmap.GetHbitmap();
            try
            {
                return System.Windows.Interop.Imaging.CreateBitmapSourceFromHBitmap(
                    hBitmap,
                    IntPtr.Zero,
                    Int32Rect.Empty,
                    BitmapSizeOptions.FromEmptyOptions());
            }
            finally
            {
                DeleteObject(hBitmap);
            }
        }
    }
}
