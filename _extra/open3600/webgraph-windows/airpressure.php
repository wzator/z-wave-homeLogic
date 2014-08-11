<?php
include 'graph.php';

$fil=fopen("./log3600.log","r");
$i=0;
fseek ($fil, -130000, SEEK_END);
$streng = fgets($fil, 1000);
while (!feof($fil)) {
    $streng = fgets($fil, 1000);
    $components = preg_split("/[\s]/", $streng);
    if (IsSet($components[15]))
    {
        $time[$i]= $components[2];
        $date[$i]= $components[1];
        $pressure[$i]= $components[15];
        $i++;
    }    
}
fclose($fil);

$numberof = count($time);
$start = $numberof - (24*6*8);



//Pressure First
$line = new graph(640,480);
$line->parameter['label_font'] = 'arial.ttf';
$line->parameter['title'] = 'Pressure';
$line->parameter['x_label'] = 'Day';
$line->parameter['x_axis_text'] = 24*6;
$line->parameter['x_grid'] = 'none';
$line->parameter['x_axis_angle'] = 60;
$line->parameter['tick_length'] = 0;
$line->parameter['y_label_left'] = 'hPa';
$line->parameter['y_min_left'] = 960;
$line->parameter['y_max_left'] = 1050;
$line->parameter['y_decimal']= 0;
//$line->parameter['num_x_ticks'] = 7;
$line->parameter['y_axis_gridlines'] = 10;
$line->parameter['point_size'] = 6;
$line->parameter['shadow'] = 'none';

$i=$start;
while (substr($time[$i],0,5) != "00:00")
{
    $i++;
}
$start=$i-1;

for ($i=$start,$j=0 ; $i < $numberof ; $i++,$j++)
{

    $line->x_data[$j]= substr($date[$i],5,10);

/*    if (substr($time[$i],0,5) == "00:00")
    {
        $line->x_data[$j]= substr($date[$i],0,6);
    }
    else
    {
        $line->x_data[$j]= "";
    }
*/
//    $line->x_data[$j]= $time[$i];
    $line->y_data['Pressure'][$j]= $pressure[$i];
}

// format for each data set
$line->y_format['Pressure'] = 
  array('colour' => 'red', 'line' => 'line', 'point' => 'dot');

// order in which to draw data sets.
$line->y_order = array('Pressure');

// draw it.
$line->draw();



?>
