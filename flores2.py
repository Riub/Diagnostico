from kivy.app import App
from kivy.uix.widget import Widget
from kivy.graphics import Line, Color, Ellipse
from kivy.uix.floatlayout import FloatLayout
import math
import colorsys

phi = 137.508 * (math.pi / 180)  # Convertir phi a radianes

class FlowerWidget(Widget):

    def __init__(self, **kwargs):
        super(FlowerWidget, self).__init__(**kwargs)
        self.bind(size=self.update_canvas)
        self.draw_stem_with_leaf()
        self.draw_flower(center_radius=100)

    def update_canvas(self, *args):
        self.canvas.clear()
        self.draw_stem_with_leaf()
        self.draw_flower(center_radius=100)

    def draw_stem_with_leaf(self):
        with self.canvas:
            # Dibujar el tallo centrado en la pantalla
            Color(0, 1, 0)
            Line(points=[self.center_x, self.center_y, self.center_x, self.center_y - 200], width=5)

            # Dibujar una hoja pequeña y en posición horizontal (hacia la izquierda del tallo)
            Color(0, 1, 0, 0.6)
            Ellipse(pos=(self.center_x - 50, self.center_y - 150), size=(60, 30))

    def draw_flower(self, center_radius):
        with self.canvas:
            for i in range(16):
                angle = i * (360 / 16)  # Dividir en 16 pétalos
                radius = center_radius
                x = self.center_x + radius * math.cos(math.radians(angle))
                y = self.center_y + radius * math.sin(math.radians(angle))

                Color(*colorsys.hsv_to_rgb(i / 16.0, 1, 1))  # Cambiar color en cada pétalo
                Ellipse(pos=(x - 30, y - 30), size=(60, 30))  # Dibujar pétalos

class FlowerApp(App):
    def build(self):
        layout = FloatLayout()
        flower_widget = FlowerWidget()
        layout.add_widget(flower_widget)
        return layout

if __name__ == '__main__':
    FlowerApp().run()
